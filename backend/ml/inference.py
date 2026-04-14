from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from joblib import load

from .schema import CANONICAL_FEATURES, METRICS_PATH, MODEL_INFO_PATH, MODEL_PATH

# ---------------------------------------------------------------------------
# Sentinel set for fast detection of canonical-feature payloads.
# If an incoming dict contains ANY of these keys we treat it as primary mode.
# ---------------------------------------------------------------------------
_CANONICAL_KEY_SET: frozenset[str] = frozenset(CANONICAL_FEATURES)

# Legacy-field → canonical-feature mapping used by the backward-compat layer.
_LEGACY_TO_CANONICAL: dict[str, str] = {
    "destination_port":    "destination_port",
    "duration":            "flow_duration",
    "duration_seconds":    "flow_duration",
    "packets_per_second":  "flow_packets_per_s",
    "bytes_per_second":    "flow_bytes_per_s",
    "forward_packets":     "total_fwd_packets",
    "backward_packets":    "total_bwd_packets",
    "forward_bytes":       "total_length_fwd_packets",
    "backward_bytes":      "total_length_bwd_packets",
}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


@dataclass
class PredictionOutput:
    label: str
    confidence: float
    stability_score: float
    model_version: str
    reasoning: str
    alternative_hypothesis: str
    triggered_indicators: list[str]
    feature_snapshot: dict[str, Any]


class MLPredictor:
    def __init__(self, model_path: str | Path = MODEL_PATH):
        self.model_path = Path(model_path)
        self.pipeline = None
        self.model_info = self._load_json(MODEL_INFO_PATH)
        self.metrics = self._load_json(METRICS_PATH)
        self.available = False
        self.model_version = "heuristic-fallback"

        if self.model_path.exists():
            try:
                self.pipeline = load(self.model_path)
                self.available = True
                self.model_version = self.model_info.get("model_version", "rf-cic-77f-v2")
            except Exception:
                pass

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def predict_from_features(
        self,
        features: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> PredictionOutput:
        """Primary inference path.

        ``features`` should be a dict whose keys are canonical 77-feature names.
        Any missing keys default to 0.0 after normalization.
        """
        normalized = self._normalize_features(features)
        return self._run_inference(normalized, context or {})

    def predict_from_event(self, event: dict[str, Any]) -> PredictionOutput:
        """Dispatch to the appropriate inference path.

        If the event already contains canonical 77-feature keys (e.g. flow_duration,
        total_fwd_packets) it is forwarded directly to predict_from_features().
        Otherwise the legacy 10-field event is mapped to the 77-feature schema
        via _event_to_features() — a degraded compatibility path where the ~69
        unmapped features default to 0.0.
        """
        if _CANONICAL_KEY_SET.intersection(event):
            return self.predict_from_features(event, context=event)
        # [DEGRADED COMPAT] Legacy event fields → 77-feature schema.
        return self.predict_from_features(self._event_to_features(event), context=event)

    # ------------------------------------------------------------------
    # Feature normalization
    # ------------------------------------------------------------------

    def _normalize_features(self, features: dict[str, Any]) -> dict[str, float]:
        """Return a dict with exactly the 77 canonical features, all non-negative floats."""
        normalized: dict[str, float] = {}
        for feat in CANONICAL_FEATURES:
            normalized[feat] = max(_safe_float(features.get(feat)), 0.0)
        return normalized

    def _event_to_features(self, event: dict[str, Any]) -> dict[str, Any]:
        """[DEGRADED COMPAT] Map a legacy 10-field event dict to the 77-feature schema.

        Only 8 fields have direct equivalents; all others default to 0.0.
        This path intentionally accepts reduced accuracy because critical flow
        statistics (IAT, header lengths, flag counts, window sizes …) are absent.
        """
        duration = max(_safe_float(event.get("duration_seconds") or event.get("duration")), 0.1)
        bytes_total = max(_safe_float(event.get("bytes_transferred_kb"), 0.0) * 1024.0, 0.0)
        packets_rate = max(_safe_float(event.get("packets_per_second"), 0.0), 0.0)
        packets_total = packets_rate * duration

        return {
            "destination_port":         _safe_int(event.get("destination_port")),
            "flow_duration":            duration,
            "flow_bytes_per_s":         bytes_total / duration if duration > 0 else 0.0,
            "flow_packets_per_s":       packets_rate,
            "total_fwd_packets":        packets_total * 0.58,
            "total_bwd_packets":        packets_total * 0.42,
            "total_length_fwd_packets": bytes_total * 0.62,
            "total_length_bwd_packets": bytes_total * 0.38,
            # All other 69 features are absent in legacy events and default to 0.0.
        }

    # ------------------------------------------------------------------
    # Inference core
    # ------------------------------------------------------------------

    def _run_inference(
        self,
        normalized: dict[str, float],
        context: dict[str, Any],
    ) -> PredictionOutput:
        if self.available and self.pipeline is not None:
            try:
                frame = pd.DataFrame([normalized], columns=CANONICAL_FEATURES)
                probabilities = self.pipeline.predict_proba(frame)[0]
                attack_probability = float(probabilities[1])
                stability = self._stability_score(normalized)
            except Exception:
                # Model schema mismatch (e.g. stale artifact) — fall through to heuristic.
                attack_probability = self._heuristic_probability(normalized, context)
                stability = self._heuristic_stability(normalized, attack_probability)
        else:
            attack_probability = self._heuristic_probability(normalized, context)
            stability = self._heuristic_stability(normalized, attack_probability)

        confidence = attack_probability if attack_probability >= 0.5 else 1.0 - attack_probability
        label = "Attack" if attack_probability >= 0.5 else "Benign"

        indicators = self._build_indicators(normalized, context)
        reasoning = self._build_reasoning(label, normalized, indicators)
        alternative = self._alternative_hypothesis(label, normalized)

        return PredictionOutput(
            label=label,
            confidence=round(confidence, 4),
            stability_score=round(stability, 4),
            model_version=self.model_version,
            reasoning=reasoning,
            alternative_hypothesis=alternative,
            triggered_indicators=indicators,
            feature_snapshot=normalized,
        )

    # ------------------------------------------------------------------
    # Stability scoring
    # ------------------------------------------------------------------

    def _stability_score(self, features: dict[str, float]) -> float:
        """Perturb the five most predictive flow-rate features and measure variance."""
        if self.pipeline is None:
            return self._heuristic_stability(features, 0.5)

        perturb_keys = [
            "flow_bytes_per_s",
            "flow_packets_per_s",
            "flow_duration",
            "total_fwd_packets",
            "total_bwd_packets",
        ]
        frame = pd.DataFrame([features], columns=CANONICAL_FEATURES)
        baseline = float(self.pipeline.predict_proba(frame)[0][1])

        variants: list[float] = []
        for multiplier in (0.95, 1.05):
            variant = dict(features)
            for key in perturb_keys:
                variant[key] = variant[key] * multiplier
            try:
                vframe = pd.DataFrame([variant], columns=CANONICAL_FEATURES)
                variants.append(float(self.pipeline.predict_proba(vframe)[0][1]))
            except Exception:
                pass

        if not variants:
            return 0.75
        spread = np.std([baseline, *variants])
        return float(max(0.05, min(0.99, 1.0 - (spread * 4.5))))

    def _heuristic_probability(self, features: dict[str, float], context: dict[str, Any]) -> float:
        score = 0.16
        if features["destination_port"] in {22, 23, 3389, 445, 3306, 1433}:
            score += 0.16
        if features["flow_packets_per_s"] > 550:
            score += 0.19
        if features["flow_bytes_per_s"] > 250_000:
            score += 0.16
        if features["syn_flag_count"] > 10:
            score += 0.12
        if features["rst_flag_count"] > 5:
            score += 0.08
        if context.get("known_bad_source"):
            score += 0.18
        if context.get("off_hours_activity"):
            score += 0.08
        if context.get("repeated_attempts"):
            score += 0.09
        if context.get("failed_logins", 0) >= 6:
            score += 0.18
        return max(0.01, min(0.99, score))

    def _heuristic_stability(self, features: dict[str, float], probability: float) -> float:
        score = 0.46 + (abs(probability - 0.5) * 0.9)
        if features["flow_packets_per_s"] > 550:
            score += 0.07
        if features["flow_bytes_per_s"] > 250_000:
            score += 0.05
        return float(max(0.05, min(0.98, score)))

    # ------------------------------------------------------------------
    # Human-readable output helpers
    # ------------------------------------------------------------------

    def _build_indicators(
        self, features: dict[str, float], context: dict[str, Any]
    ) -> list[str]:
        indicators: list[str] = []
        if context.get("known_bad_source"):
            indicators.append("Threat-intelligence context marks the source as high-risk.")
        if features["destination_port"] in {22, 23, 3389, 445, 3306, 1433}:
            indicators.append("Traffic targets a commonly abused administrative service port.")
        if features["flow_packets_per_s"] > 550:
            indicators.append("Packet rate exceeds the attack-oriented range observed during training.")
        if features["flow_bytes_per_s"] > 250_000:
            indicators.append("Byte throughput is unusually high for a normal application flow.")
        if features["syn_flag_count"] > 10:
            indicators.append("Elevated SYN flag count is consistent with scanning or SYN-flood activity.")
        if features["rst_flag_count"] > 5:
            indicators.append("Multiple RST flags suggest abrupt connection terminations or port scanning.")
        if context.get("failed_logins", 0) >= 6:
            indicators.append("Authentication failures increase the likelihood of malicious intent.")
        if context.get("repeated_attempts"):
            indicators.append("Repeated attempts suggest scanning or brute-force behavior.")
        if context.get("off_hours_activity"):
            indicators.append("The event occurs outside the expected operational time window.")
        if not indicators:
            indicators.append("Observed flow statistics remain close to the benign operating profile.")
        return indicators

    def _build_reasoning(
        self,
        label: str,
        features: dict[str, float],
        indicators: list[str],
    ) -> str:
        if label == "Benign":
            return (
                "The model keeps this event in the benign class because the combined "
                "flow duration, packet rate and throughput stay near the benign profile."
            )
        return f"The model predicts {label} because {indicators[0].lower()}"

    def _alternative_hypothesis(self, label: str, features: dict[str, float]) -> str:
        if label == "Benign":
            return (
                "An attack explanation remains possible only if contextual evidence "
                "outside the flow record contradicts the benign pattern."
            )
        if features["flow_bytes_per_s"] > 250_000:
            return "A large but legitimate bulk transfer is the main benign alternative."
        return "Short-lived noisy traffic burst is the main benign alternative."
