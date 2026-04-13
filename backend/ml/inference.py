from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from joblib import load

from .schema import CANONICAL_FEATURES, METRICS_PATH, MODEL_INFO_PATH, MODEL_PATH


class FeatureValidationError(ValueError):
    """Raised when the canonical feature vector fails pre-prediction validation."""


def validate_canonical_features(
    features: dict[str, Any],
    feature_order: list[str],
) -> None:
    """Raise FeatureValidationError if any required canonical features are missing, NaN, or Inf.

    This is the single gate that must be passed before every model.predict_proba call
    when input comes through the canonical (non-legacy) code path.
    """
    missing = [f for f in feature_order if f not in features]
    if missing:
        raise FeatureValidationError(
            f"predict_from_features requires all {len(feature_order)} canonical features. "
            f"Missing {len(missing)}: {missing[:8]}{'...' if len(missing) > 8 else ''}. "
            "Use predict_from_event() for simplified/legacy event payloads."
        )

    bad: list[str] = []
    for name in feature_order:
        try:
            v = float(features[name])
            if not math.isfinite(v):
                bad.append(f"{name}={features[name]!r}")
        except (TypeError, ValueError):
            bad.append(f"{name}={features[name]!r}")
    if bad:
        raise FeatureValidationError(
            f"Non-finite or non-numeric canonical features: "
            f"{bad[:8]}{'...' if len(bad) > 8 else ''}"
        )


LEGACY_TO_CANONICAL = {
    "destination_port": "destination_port",
    "duration": "flow_duration",
    "duration_seconds": "flow_duration",
    "packets_per_second": "flow_packets_per_s",
    "bytes_per_second": "flow_bytes_per_s",
    "forward_packets": "total_fwd_packets",
    "backward_packets": "total_bwd_packets",
    "forward_bytes": "total_length_fwd_packets",
    "backward_bytes": "total_length_bwd_packets",
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


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return float(max(low, min(high, value)))


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
    """RandomForest inference wrapper for the 77-feature flow schema."""

    def __init__(
        self,
        model_path: str | Path = MODEL_PATH,
        *,
        model_info_path: str | Path = MODEL_INFO_PATH,
        metrics_path: str | Path = METRICS_PATH,
    ):
        self.model_path = Path(model_path)
        self.model_info_path = Path(model_info_path)
        self.metrics_path = Path(metrics_path)
        self.pipeline = None
        self.model_info = self._load_json(self.model_info_path)
        self.metrics = self._load_json(self.metrics_path)
        self.available = False
        self.model_version = self.model_info.get("model_version", "rf-flow-77-cic-unsw-v2")
        self.feature_order = list(CANONICAL_FEATURES)

        if self.model_path.exists():
            self.pipeline = load(self.model_path)
            self.available = True
            self._validate_feature_order()
        else:
            self.model_version = "heuristic-fallback"

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def predict_from_event(self, event: dict[str, Any]) -> PredictionOutput:
        """Legacy code path: approximate the 77-feature schema from simplified event fields.

        Use this when the caller provides a reduced event payload (e.g. from the REST API
        or CSV import with partial columns).  The approximation is intentional and explicit —
        do NOT use this path when all 77 canonical features are available.
        """
        normalized = self._normalize_legacy(event)
        return self._run_prediction(normalized, context=event)

    def predict_from_features(
        self,
        features: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> PredictionOutput:
        """Strict canonical code path: all 77 features must be present, finite, and numeric.

        Raises FeatureValidationError if any feature is missing, NaN, or Inf.
        Use predict_from_event() for simplified/legacy event payloads.
        """
        validate_canonical_features(features, self.feature_order)
        normalized = {name: max(float(features[name]), 0.0) for name in self.feature_order}
        return self._run_prediction(normalized, context=context or {})

    def _frame_from_features(self, normalized: dict[str, float]) -> pd.DataFrame:
        ordered_row = [[normalized[feature_name] for feature_name in self.feature_order]]
        return pd.DataFrame(ordered_row, columns=self.feature_order)

    def _validate_feature_order(self) -> None:
        if self.pipeline is None:
            return
        model_features = getattr(self.pipeline, "feature_names_in_", None)
        if model_features is None:
            return
        model_order = [str(feature_name) for feature_name in model_features]
        if model_order != self.feature_order:
            raise ValueError(
                "rf_ids_features.json does not match the model feature order. "
                "Update rf_ids_features.json or replace the model artifact."
            )

    def _normalize_features(self, features: dict[str, Any]) -> dict[str, float]:
        direct_keys = {
            feature_name
            for feature_name in self.feature_order
            if feature_name in features and str(features.get(feature_name)).strip() != ""
        }

        normalized = {feature_name: 0.0 for feature_name in self.feature_order}
        for feature_name in self.feature_order:
            if feature_name in features:
                normalized[feature_name] = max(_safe_float(features.get(feature_name)), 0.0)

        compatibility = self._legacy_feature_compatibility(features)
        for feature_name, value in compatibility.items():
            if feature_name not in direct_keys:
                normalized[feature_name] = max(_safe_float(value), 0.0)

        return normalized

    def _legacy_feature_compatibility(self, payload: dict[str, Any]) -> dict[str, float]:
        """Approximate the 77-feature schema from older simplified event payloads."""

        duration = max(
            _safe_float(payload.get("flow_duration")),
            _safe_float(payload.get("duration")),
            _safe_float(payload.get("duration_seconds")),
            0.0,
        )
        destination_port = _safe_int(payload.get("destination_port"))
        protocol = str(payload.get("protocol", "UNKNOWN")).upper()
        total_fwd_packets = max(
            _safe_float(payload.get("total_fwd_packets")),
            _safe_float(payload.get("forward_packets")),
            0.0,
        )
        total_bwd_packets = max(
            _safe_float(payload.get("total_bwd_packets")),
            _safe_float(payload.get("backward_packets")),
            0.0,
        )
        total_packets = total_fwd_packets + total_bwd_packets

        total_length_fwd_packets = max(
            _safe_float(payload.get("total_length_fwd_packets")),
            _safe_float(payload.get("forward_bytes")),
            0.0,
        )
        total_length_bwd_packets = max(
            _safe_float(payload.get("total_length_bwd_packets")),
            _safe_float(payload.get("backward_bytes")),
            0.0,
        )
        total_bytes = total_length_fwd_packets + total_length_bwd_packets

        bytes_transferred_kb = max(_safe_float(payload.get("bytes_transferred_kb")), 0.0)
        if total_bytes == 0.0 and bytes_transferred_kb > 0.0:
            total_bytes = bytes_transferred_kb * 1024.0
            total_length_fwd_packets = total_bytes * 0.62
            total_length_bwd_packets = total_bytes * 0.38

        flow_packets_per_s = max(
            _safe_float(payload.get("flow_packets_per_s")),
            _safe_float(payload.get("packets_per_second")),
            (total_packets / duration) if duration > 0 and total_packets > 0 else 0.0,
        )
        flow_bytes_per_s = max(
            _safe_float(payload.get("flow_bytes_per_s")),
            _safe_float(payload.get("bytes_per_second")),
            (total_bytes / duration) if duration > 0 and total_bytes > 0 else 0.0,
        )

        if total_packets == 0 and duration > 0 and flow_packets_per_s > 0:
            total_packets = flow_packets_per_s * duration
            total_fwd_packets = total_packets * 0.58
            total_bwd_packets = total_packets * 0.42

        if total_bytes == 0 and duration > 0 and flow_bytes_per_s > 0:
            total_bytes = flow_bytes_per_s * duration
            total_length_fwd_packets = total_bytes * 0.62
            total_length_bwd_packets = total_bytes * 0.38

        fwd_packets_per_s = (total_fwd_packets / duration) if duration > 0 else 0.0
        bwd_packets_per_s = (total_bwd_packets / duration) if duration > 0 else 0.0
        avg_fwd_segment_size = (
            total_length_fwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0.0
        )
        avg_bwd_segment_size = (
            total_length_bwd_packets / total_bwd_packets if total_bwd_packets > 0 else 0.0
        )
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0.0
        packet_length_std = avg_packet_size * 0.18 if avg_packet_size > 0 else 0.0
        packet_length_variance = packet_length_std**2
        packet_length_max = avg_packet_size * 1.55 if avg_packet_size > 0 else 0.0
        packet_length_min = max(avg_packet_size * 0.35, 0.0) if avg_packet_size > 0 else 0.0
        fwd_packet_length_mean = avg_fwd_segment_size
        bwd_packet_length_mean = avg_bwd_segment_size
        fwd_packet_length_std = avg_fwd_segment_size * 0.15 if avg_fwd_segment_size > 0 else 0.0
        bwd_packet_length_std = avg_bwd_segment_size * 0.15 if avg_bwd_segment_size > 0 else 0.0
        flow_iat_mean = duration / max(total_packets - 1, 1) if total_packets > 1 else duration
        fwd_iat_mean = duration / max(total_fwd_packets - 1, 1) if total_fwd_packets > 1 else duration
        bwd_iat_mean = duration / max(total_bwd_packets - 1, 1) if total_bwd_packets > 1 else duration
        repeated_attempts = bool(payload.get("repeated_attempts")) or flow_packets_per_s > 400
        known_bad_source = bool(payload.get("known_bad_source"))
        failed_logins = _safe_int(payload.get("failed_logins"))
        source_port = _safe_int(payload.get("source_port"))
        syn_pressure = 1.0 if repeated_attempts or destination_port in {22, 23, 3389} else 0.0
        ack_activity = min(total_packets / 100.0, 32.0)
        rst_activity = 1.0 if known_bad_source or failed_logins >= 6 else 0.0
        psh_activity = 1.0 if flow_bytes_per_s > 200000 else 0.0
        urg_activity = 1.0 if failed_logins >= 8 else 0.0
        header_size = 20.0 if protocol == "TCP" else 8.0

        compatibility = {
            LEGACY_TO_CANONICAL[key]: value
            for key, value in payload.items()
            if key in LEGACY_TO_CANONICAL
        }
        compatibility.update(
            {
                "destination_port": float(destination_port),
                "flow_duration": duration,
                "flow_packets_per_s": flow_packets_per_s,
                "flow_bytes_per_s": flow_bytes_per_s,
                "total_fwd_packets": total_fwd_packets,
                "total_bwd_packets": total_bwd_packets,
                "total_length_fwd_packets": total_length_fwd_packets,
                "total_length_bwd_packets": total_length_bwd_packets,
                "subflow_fwd_packets": total_fwd_packets,
                "subflow_bwd_packets": total_bwd_packets,
                "subflow_fwd_bytes": total_length_fwd_packets,
                "subflow_bwd_bytes": total_length_bwd_packets,
                "fwd_packets_per_s": fwd_packets_per_s,
                "bwd_packets_per_s": bwd_packets_per_s,
                "avg_fwd_segment_size": avg_fwd_segment_size,
                "avg_bwd_segment_size": avg_bwd_segment_size,
                "avg_packet_size": avg_packet_size,
                "packet_length_mean": avg_packet_size,
                "packet_length_max": packet_length_max,
                "packet_length_min": packet_length_min,
                "packet_length_std": packet_length_std,
                "packet_length_variance": packet_length_variance,
                "fwd_packet_length_mean": fwd_packet_length_mean,
                "fwd_packet_length_max": avg_fwd_segment_size * 1.5 if avg_fwd_segment_size > 0 else 0.0,
                "fwd_packet_length_min": max(avg_fwd_segment_size * 0.35, 0.0),
                "fwd_packet_length_std": fwd_packet_length_std,
                "bwd_packet_length_mean": bwd_packet_length_mean,
                "bwd_packet_length_max": avg_bwd_segment_size * 1.5 if avg_bwd_segment_size > 0 else 0.0,
                "bwd_packet_length_min": max(avg_bwd_segment_size * 0.35, 0.0),
                "bwd_packet_length_std": bwd_packet_length_std,
                "flow_iat_mean": flow_iat_mean,
                "flow_iat_max": flow_iat_mean * 1.6,
                "flow_iat_min": flow_iat_mean * 0.4 if flow_iat_mean > 0 else 0.0,
                "flow_iat_std": flow_iat_mean * 0.25 if flow_iat_mean > 0 else 0.0,
                "fwd_iat_total": duration,
                "fwd_iat_mean": fwd_iat_mean,
                "fwd_iat_max": fwd_iat_mean * 1.6,
                "fwd_iat_min": fwd_iat_mean * 0.4 if fwd_iat_mean > 0 else 0.0,
                "fwd_iat_std": fwd_iat_mean * 0.25 if fwd_iat_mean > 0 else 0.0,
                "bwd_iat_total": duration,
                "bwd_iat_mean": bwd_iat_mean,
                "bwd_iat_max": bwd_iat_mean * 1.6,
                "bwd_iat_min": bwd_iat_mean * 0.4 if bwd_iat_mean > 0 else 0.0,
                "bwd_iat_std": bwd_iat_mean * 0.25 if bwd_iat_mean > 0 else 0.0,
                "down_up_ratio": total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0.0,
                "ack_flag_count": ack_activity,
                "syn_flag_count": syn_pressure,
                "rst_flag_count": rst_activity,
                "psh_flag_count": psh_activity,
                "urg_flag_count": urg_activity,
                "fwd_psh_flags": psh_activity,
                "bwd_psh_flags": 0.0,
                "fwd_urg_flags": urg_activity,
                "bwd_urg_flags": 0.0,
                "ece_flag_count": 1.0 if protocol == "TCP" and flow_packets_per_s > 700 else 0.0,
                "cwr_flag_count": 1.0 if protocol == "TCP" and known_bad_source else 0.0,
                "fin_flag_count": 1.0 if protocol == "TCP" and not repeated_attempts else 0.0,
                "fwd_header_length": total_fwd_packets * header_size,
                "bwd_header_length": total_bwd_packets * header_size,
                "init_win_bytes_forward": 2048.0 if protocol == "TCP" and source_port > 0 else 0.0,
                "init_win_bytes_backward": 2048.0 if protocol == "TCP" and destination_port > 0 else 0.0,
                "min_seg_size_forward": max(avg_fwd_segment_size * 0.3, 0.0),
                "act_data_pkt_fwd": total_fwd_packets * 0.62,
                "active_mean": duration * 0.55,
                "active_std": duration * 0.12,
                "active_max": duration * 0.72,
                "active_min": duration * 0.28,
                "idle_mean": duration * 0.45,
                "idle_std": duration * 0.10,
                "idle_max": duration * 0.60,
                "idle_min": duration * 0.18,
                "fwd_avg_bytes_bulk": 0.0,
                "fwd_avg_packets_bulk": 0.0,
                "fwd_avg_bulk_rate": 0.0,
                "bwd_avg_bytes_bulk": 0.0,
                "bwd_avg_packets_bulk": 0.0,
                "bwd_avg_bulk_rate": 0.0,
            }
        )
        return compatibility

    def _heuristic_probability(self, features: dict[str, Any], context: dict[str, Any]) -> float:
        score = 0.10
        if features["destination_port"] in {22, 23, 3389}:
            score += 0.14
        if features["flow_packets_per_s"] > 650:
            score += 0.18
        if features["flow_bytes_per_s"] > 250000:
            score += 0.14
        if features["syn_flag_count"] > 0:
            score += 0.12
        if features["rst_flag_count"] > 0:
            score += 0.10
        if features["ack_flag_count"] > 18:
            score += 0.06
        if features["down_up_ratio"] > 1.8:
            score += 0.06
        if context.get("known_bad_source"):
            score += 0.15
        if context.get("off_hours_activity"):
            score += 0.07
        if context.get("repeated_attempts"):
            score += 0.08
        if context.get("failed_logins", 0) >= 6:
            score += 0.16
        return _clamp(score, 0.01, 0.99)

    def _heuristic_stability(self, features: dict[str, Any], probability: float) -> float:
        score = 0.44 + (abs(probability - 0.5) * 0.92)
        if features["flow_packets_per_s"] > 650:
            score += 0.06
        if features["flow_bytes_per_s"] > 250000:
            score += 0.05
        if features["syn_flag_count"] > 0:
            score += 0.04
        return _clamp(score, 0.05, 0.98)

    def _stability_score(self, features: dict[str, Any]) -> float:
        if self.pipeline is None:
            return self._heuristic_stability(features, 0.5)

        baseline = self._predict_attack_probability(features)
        variants = []
        for multipliers in (
            {
                "flow_bytes_per_s": 0.95,
                "flow_packets_per_s": 0.95,
                "total_fwd_packets": 0.96,
                "total_bwd_packets": 0.96,
            },
            {
                "flow_bytes_per_s": 1.05,
                "flow_packets_per_s": 1.05,
                "total_fwd_packets": 1.04,
                "total_bwd_packets": 1.04,
            },
            {
                "flow_duration": 0.94,
                "flow_packets_per_s": 1.02,
            },
            {
                "flow_duration": 1.06,
                "flow_bytes_per_s": 0.98,
            },
        ):
            variant = dict(features)
            for feature_name, multiplier in multipliers.items():
                variant[feature_name] = max(_safe_float(variant.get(feature_name)) * multiplier, 0.0)
            variants.append(self._predict_attack_probability(variant))

        spread = np.std([baseline, *variants])
        return _clamp(1.0 - (spread * 4.5), 0.05, 0.99)

    def _predict_attack_probability(self, normalized: dict[str, float]) -> float:
        if self.pipeline is None:
            return self._heuristic_probability(normalized, {})
        frame = self._frame_from_features(normalized)
        return float(self.pipeline.predict_proba(frame)[0][1])

    def _build_indicators(self, features: dict[str, Any], context: dict[str, Any]) -> list[str]:
        indicators: list[str] = []
        if context.get("known_bad_source"):
            indicators.append("Threat-intelligence context marks the source as high-risk.")
        if features["destination_port"] in {22, 23, 3389}:
            indicators.append("The flow targets an administrative or commonly abused destination port.")
        if features["flow_packets_per_s"] > 650:
            indicators.append("Packet throughput is elevated relative to the benign flow profile.")
        if features["flow_bytes_per_s"] > 250000:
            indicators.append("Byte throughput is unusually high for a normal application flow.")
        if features["syn_flag_count"] > 0:
            indicators.append("SYN flag activity suggests scanning, brute-force, or handshake abuse.")
        if features["rst_flag_count"] > 0:
            indicators.append("RST flag activity indicates unstable or intentionally interrupted sessions.")
        if features["down_up_ratio"] > 1.8:
            indicators.append("Forward and backward packet volumes are imbalanced beyond the expected baseline.")
        if context.get("failed_logins", 0) >= 6:
            indicators.append("Authentication failures increase the likelihood of malicious intent.")
        if context.get("repeated_attempts"):
            indicators.append("Repeated attempts suggest scanning or brute-force behavior.")
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
            return (
                "The model keeps this event in the benign class because the combined "
                "flow duration, packet rate, and packet-length profile stay near the benign baseline."
            )
        return f"The model predicts {label} because {indicators[0].lower()}"

    def _alternative_hypothesis(self, label: str, features: dict[str, Any]) -> str:
        if label == "Benign":
            return "An attack explanation remains possible only if external context contradicts the observed flow baseline."
        if features["flow_bytes_per_s"] > 250000:
            return "A large but legitimate bulk transfer is the main benign alternative."
        if features["flow_packets_per_s"] > 650:
            return "A short-lived diagnostic or monitoring burst is the main benign alternative."
        return "A noisy but legitimate application flow is the main benign alternative."
