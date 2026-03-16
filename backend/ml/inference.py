from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from joblib import load

from .schema import CANONICAL_FEATURES, METRICS_PATH, MODEL_INFO_PATH, MODEL_PATH


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
            self.pipeline = load(self.model_path)
            self.available = True
            self.model_version = self.model_info.get("model_version", "rf-cic-unsw-v1")

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def predict_from_event(self, event: dict[str, Any]) -> PredictionOutput:
        features = self._event_to_features(event)
        return self.predict_from_features(features, context=event)

    def predict_from_features(
        self,
        features: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> PredictionOutput:
        normalized = self._normalize_features(features)

        if self.available and self.pipeline is not None:
            frame = pd.DataFrame([normalized], columns=CANONICAL_FEATURES)
            probabilities = self.pipeline.predict_proba(frame)[0]
            attack_probability = float(probabilities[1])
            confidence = attack_probability if attack_probability >= 0.5 else 1 - attack_probability
            label = "Attack" if attack_probability >= 0.5 else "Benign"
            stability = self._stability_score(normalized)
        else:
            attack_probability = self._heuristic_probability(normalized, context or {})
            confidence = attack_probability if attack_probability >= 0.5 else 1 - attack_probability
            label = "Attack" if attack_probability >= 0.5 else "Benign"
            stability = self._heuristic_stability(normalized, attack_probability)

        indicators = self._build_indicators(normalized, context or {})
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

    def _normalize_features(self, features: dict[str, Any]) -> dict[str, Any]:
        normalized = {
            "protocol": str(features.get("protocol", "UNKNOWN")).upper(),
            "source_port": _safe_int(features.get("source_port")),
            "destination_port": _safe_int(features.get("destination_port")),
            "duration": max(_safe_float(features.get("duration")), 0.0),
            "forward_packets": max(_safe_float(features.get("forward_packets")), 0.0),
            "backward_packets": max(_safe_float(features.get("backward_packets")), 0.0),
            "forward_bytes": max(_safe_float(features.get("forward_bytes")), 0.0),
            "backward_bytes": max(_safe_float(features.get("backward_bytes")), 0.0),
            "bytes_per_second": max(_safe_float(features.get("bytes_per_second")), 0.0),
            "packets_per_second": max(_safe_float(features.get("packets_per_second")), 0.0),
        }
        return normalized

    def _event_to_features(self, event: dict[str, Any]) -> dict[str, Any]:
        duration = max(_safe_float(event.get("duration_seconds"), 0.0), 0.1)
        bytes_total = max(_safe_float(event.get("bytes_transferred_kb"), 0.0) * 1024.0, 0.0)
        packets_rate = max(_safe_float(event.get("packets_per_second"), 0.0), 0.0)
        packets_total = packets_rate * duration
        forward_packets = packets_total * 0.58
        backward_packets = packets_total * 0.42
        forward_bytes = bytes_total * 0.62
        backward_bytes = bytes_total * 0.38

        return {
            "protocol": event.get("protocol", "UNKNOWN"),
            "source_port": event.get("source_port", 0),
            "destination_port": event.get("destination_port", 0),
            "duration": duration,
            "forward_packets": forward_packets,
            "backward_packets": backward_packets,
            "forward_bytes": forward_bytes,
            "backward_bytes": backward_bytes,
            "bytes_per_second": bytes_total / duration if duration > 0 else 0.0,
            "packets_per_second": packets_rate,
        }

    def _heuristic_probability(self, features: dict[str, Any], context: dict[str, Any]) -> float:
        score = 0.16
        if features["destination_port"] in {22, 23, 3389}:
            score += 0.16
        if features["packets_per_second"] > 550:
            score += 0.19
        if features["bytes_per_second"] > 250000:
            score += 0.16
        if context.get("known_bad_source"):
            score += 0.18
        if context.get("off_hours_activity"):
            score += 0.08
        if context.get("repeated_attempts"):
            score += 0.09
        if context.get("failed_logins", 0) >= 6:
            score += 0.18
        if features["protocol"] == "ICMP":
            score += 0.06
        return max(0.01, min(0.99, score))

    def _heuristic_stability(self, features: dict[str, Any], probability: float) -> float:
        score = 0.46 + (abs(probability - 0.5) * 0.9)
        if features["packets_per_second"] > 550:
            score += 0.07
        if features["bytes_per_second"] > 250000:
            score += 0.05
        return max(0.05, min(0.98, score))

    def _stability_score(self, features: dict[str, Any]) -> float:
        if self.pipeline is None:
            return self._heuristic_stability(features, 0.5)

        frame = pd.DataFrame([features], columns=CANONICAL_FEATURES)
        baseline = float(self.pipeline.predict_proba(frame)[0][1])
        variants = []
        for multiplier in (0.95, 1.05):
            variant = dict(features)
            variant["bytes_per_second"] *= multiplier
            variant["packets_per_second"] *= multiplier
            variant["duration"] *= multiplier
            variant_frame = pd.DataFrame([variant], columns=CANONICAL_FEATURES)
            variants.append(float(self.pipeline.predict_proba(variant_frame)[0][1]))

        spread = np.std([baseline, *variants])
        return max(0.05, min(0.99, 1.0 - (spread * 4.5)))

    def _build_indicators(self, features: dict[str, Any], context: dict[str, Any]) -> list[str]:
        indicators: list[str] = []
        if context.get("known_bad_source"):
            indicators.append("Threat-intelligence context marks the source as high-risk.")
        if features["destination_port"] in {22, 23, 3389}:
            indicators.append("Traffic targets a commonly abused administrative service port.")
        if features["packets_per_second"] > 550:
            indicators.append("Packet rate exceeds the attack-oriented range observed during training.")
        if features["bytes_per_second"] > 250000:
            indicators.append("Byte throughput is unusually high for a normal application flow.")
        if context.get("failed_logins", 0) >= 6:
            indicators.append("Authentication failures increase the likelihood of malicious intent.")
        if context.get("repeated_attempts"):
            indicators.append("Repeated attempts suggest scanning or brute-force behavior.")
        if context.get("off_hours_activity"):
            indicators.append("The event occurs outside the expected operational time window.")
        if features["protocol"] == "ICMP":
            indicators.append("ICMP activity is treated carefully because reconnaissance traffic often uses it.")
        if not indicators:
            indicators.append("Observed flow statistics remain close to the benign operating profile.")
        return indicators

    def _build_reasoning(
        self,
        label: str,
        features: dict[str, Any],
        indicators: list[str],
    ) -> str:
        if label == "Benign":
            return "The model keeps this event in the benign class because the combined flow duration, packet rate and throughput stay near the benign profile."
        return f"The model predicts {label} because {indicators[0].lower()}"

    def _alternative_hypothesis(self, label: str, features: dict[str, Any]) -> str:
        if label == "Benign":
            return "An attack explanation remains possible only if contextual evidence outside the flow record contradicts the benign pattern."
        if features["bytes_per_second"] > 250000:
            return "A large but legitimate bulk transfer is the main benign alternative."
        return "Short-lived noisy traffic burst is the main benign alternative."
