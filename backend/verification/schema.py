from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_STATE_PATH = ARTIFACTS_DIR / "verifier_model.pt"
MODEL_INFO_PATH = ARTIFACTS_DIR / "verifier_model_info.json"
METRICS_PATH = ARTIFACTS_DIR / "verifier_metrics.json"

EVENT_FEATURE_NAMES = [
    "duration_seconds_norm",
    "bytes_transferred_kb_log",
    "packets_per_second_log",
    "failed_logins_norm",
    "anomaly_score",
    "context_risk_score",
    "source_port_norm",
    "destination_port_norm",
    "known_bad_source",
    "off_hours_activity",
    "repeated_attempts",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "protocol_other",
]

DETECTOR_FEATURE_NAMES = [
    "detector_is_threat",
    "detector_confidence",
    "detector_stability_score",
    "triggered_indicators_count_norm",
]

PERTURBATION_FEATURE_NAMES = [
    "perturbation_mean_confidence",
    "perturbation_min_confidence",
    "perturbation_max_confidence",
    "perturbation_std_confidence",
    "perturbation_confidence_drop",
    "perturbation_variance",
    "label_consistency_ratio",
]

DERIVED_FEATURE_NAMES = [
    "context_consistency_score",
    "cross_evidence_score",
    "support_alignment_score",
    # Raw indicator flags exposed individually so the MLP can learn their weights
    # instead of relying on the hardcoded coefficients inside cross_evidence_score.
    "indicator_risky_port",
    "indicator_failed_logins_high",
    "indicator_high_pps",
    "indicator_high_bytes",
]

VERIFIER_FEATURE_NAMES = [
    *EVENT_FEATURE_NAMES,
    *DETECTOR_FEATURE_NAMES,
    *PERTURBATION_FEATURE_NAMES,
    *DERIVED_FEATURE_NAMES,
]

BENIGN_STATUS = "Benign"
VERIFIED_THREAT_STATUS = "Verified Threat"
SUSPICIOUS_STATUS = "Suspicious"


@dataclass(slots=True)
class PerturbationSummary:
    """Aggregated detector behavior over small feature perturbations."""

    mean_confidence: float
    min_confidence: float
    max_confidence: float
    std_confidence: float
    confidence_drop: float
    variance: float
    label_consistency_ratio: float
    samples: list[dict[str, Any]]


@dataclass(slots=True)
class VerificationFeatureBundle:
    """Tabular verifier inputs plus explainable intermediate metrics."""

    vector: list[float]
    feature_map: dict[str, float]
    perturbation: PerturbationSummary
    context_consistency_score: float
    cross_evidence_score: float
    support_alignment_score: float
