from __future__ import annotations

import math
from typing import Any

import numpy as np

from ml.inference import MLPredictor, PredictionOutput

from .schema import PerturbationSummary, VERIFIER_FEATURE_NAMES, VerificationFeatureBundle


def detector_attack_probability(label: str, confidence: float) -> float:
    """Convert detector label + confidence into attack-class probability."""

    bounded = float(max(0.0, min(1.0, confidence)))
    return bounded if label != "Benign" else 1.0 - bounded


def build_verification_features(
    predictor: MLPredictor,
    event: dict[str, Any],
    detector_output: PredictionOutput,
) -> VerificationFeatureBundle:
    """Assemble numeric verifier inputs from event, detector, and perturbations."""

    detector_snapshot = detector_output.feature_snapshot
    perturbation = run_perturbation_analysis(
        predictor=predictor,
        detector_snapshot=detector_snapshot,
        event=event,
        detector_output=detector_output,
    )
    context_score = context_consistency_score(event=event, detector_output=detector_output)
    evidence_score = cross_evidence_score(event=event, detector_output=detector_output)

    benign_alignment = (
        (1.0 - float(event.get("anomaly_score", 0.0)))
        + (1.0 - float(event.get("context_risk_score", 0.0)))
        + (1.0 - evidence_score)
    ) / 3.0
    threat_alignment = (context_score + evidence_score + detector_output.confidence) / 3.0
    support_alignment = benign_alignment if detector_output.label == "Benign" else threat_alignment

    feature_map = {
        **event_feature_map(event),
        **detector_feature_map(detector_output),
        **perturbation_feature_map(perturbation),
        "context_consistency_score": round(context_score, 6),
        "cross_evidence_score": round(evidence_score, 6),
        "support_alignment_score": round(float(max(0.0, min(1.0, support_alignment))), 6),
    }

    vector = [float(feature_map[name]) for name in VERIFIER_FEATURE_NAMES]
    return VerificationFeatureBundle(
        vector=vector,
        feature_map=feature_map,
        perturbation=perturbation,
        context_consistency_score=context_score,
        cross_evidence_score=evidence_score,
        support_alignment_score=float(max(0.0, min(1.0, support_alignment))),
    )


def event_feature_map(event: dict[str, Any]) -> dict[str, float]:
    """Numeric event/context features for the verifier MLP."""

    protocol = str(event.get("protocol", "UNKNOWN")).upper()
    return {
        "duration_seconds_norm": min(_safe_float(event.get("duration_seconds")) / 60.0, 1.0),
        "bytes_transferred_kb_log": min(math.log1p(_safe_float(event.get("bytes_transferred_kb"))) / 10.0, 1.0),
        "packets_per_second_log": min(math.log1p(_safe_float(event.get("packets_per_second"))) / 10.0, 1.0),
        "failed_logins_norm": min(_safe_float(event.get("failed_logins")) / 12.0, 1.0),
        "anomaly_score": _clamp01(_safe_float(event.get("anomaly_score"))),
        "context_risk_score": _clamp01(_safe_float(event.get("context_risk_score"))),
        "source_port_norm": min(_safe_float(event.get("source_port")) / 65535.0, 1.0),
        "destination_port_norm": min(_safe_float(event.get("destination_port")) / 65535.0, 1.0),
        "known_bad_source": 1.0 if bool(event.get("known_bad_source")) else 0.0,
        "off_hours_activity": 1.0 if bool(event.get("off_hours_activity")) else 0.0,
        "repeated_attempts": 1.0 if bool(event.get("repeated_attempts")) else 0.0,
        "protocol_tcp": 1.0 if protocol == "TCP" else 0.0,
        "protocol_udp": 1.0 if protocol == "UDP" else 0.0,
        "protocol_icmp": 1.0 if protocol == "ICMP" else 0.0,
        "protocol_other": 1.0 if protocol not in {"TCP", "UDP", "ICMP"} else 0.0,
    }


def detector_feature_map(detector_output: PredictionOutput) -> dict[str, float]:
    """Numeric Stage 1 detector outputs exposed to the verifier."""

    return {
        "detector_is_threat": 1.0 if detector_output.label != "Benign" else 0.0,
        "detector_confidence": _clamp01(detector_output.confidence),
        "detector_stability_score": _clamp01(detector_output.stability_score),
        "triggered_indicators_count_norm": min(len(detector_output.triggered_indicators) / 8.0, 1.0),
    }


def perturbation_feature_map(summary: PerturbationSummary) -> dict[str, float]:
    """Compact perturbation metrics included in the verifier input vector."""

    return {
        "perturbation_mean_confidence": _clamp01(summary.mean_confidence),
        "perturbation_min_confidence": _clamp01(summary.min_confidence),
        "perturbation_max_confidence": _clamp01(summary.max_confidence),
        "perturbation_std_confidence": _clamp01(summary.std_confidence),
        "perturbation_confidence_drop": _clamp01(summary.confidence_drop),
        "perturbation_variance": _clamp01(summary.variance),
        "label_consistency_ratio": _clamp01(summary.label_consistency_ratio),
    }


def context_consistency_score(event: dict[str, Any], detector_output: PredictionOutput) -> float:
    """Measure how strongly behavioral context supports the detector interpretation."""

    anomaly_score = _clamp01(_safe_float(event.get("anomaly_score")))
    context_risk = _clamp01(_safe_float(event.get("context_risk_score")))
    off_hours_bonus = 0.08 if bool(event.get("off_hours_activity")) else 0.0
    attempts_bonus = 0.10 if bool(event.get("repeated_attempts")) else 0.0
    known_bad_bonus = 0.18 if bool(event.get("known_bad_source")) else 0.0

    if detector_output.label == "Benign":
        score = 1.0 - ((anomaly_score * 0.55) + (context_risk * 0.45))
        score -= off_hours_bonus * 0.5
        score -= attempts_bonus * 0.35
        score -= known_bad_bonus * 0.7
    else:
        score = (context_risk * 0.45) + (anomaly_score * 0.35) + off_hours_bonus + attempts_bonus + known_bad_bonus
    return float(max(0.0, min(1.0, score)))


def cross_evidence_score(event: dict[str, Any], detector_output: PredictionOutput) -> float:
    """Rule-based support score used as an interpretable verifier input."""

    score = 0.10
    destination_port = int(_safe_float(event.get("destination_port")))
    packets_per_second = _safe_float(event.get("packets_per_second"))
    bytes_kb = _safe_float(event.get("bytes_transferred_kb"))
    failed_logins = int(_safe_float(event.get("failed_logins")))
    indicators_count = len(detector_output.triggered_indicators)

    if bool(event.get("known_bad_source")):
        score += 0.22
    if destination_port in {22, 23, 3389}:
        score += 0.14
    if failed_logins >= 6:
        score += 0.20
    if packets_per_second >= 550:
        score += 0.16
    if bytes_kb >= 9000:
        score += 0.10
    if bool(event.get("repeated_attempts")):
        score += 0.10
    if bool(event.get("off_hours_activity")):
        score += 0.06
    if indicators_count:
        score += min(indicators_count * 0.05, 0.16)
    if "diagnostics-window" in [str(tag) for tag in event.get("tags", [])]:
        score -= 0.16
    return float(max(0.0, min(1.0, score)))


def run_perturbation_analysis(
    predictor: MLPredictor,
    detector_snapshot: dict[str, Any],
    event: dict[str, Any],
    detector_output: PredictionOutput,
) -> PerturbationSummary:
    """Re-run the detector over nearby feature variants and summarize stability."""

    baseline_probability = detector_attack_probability(detector_output.label, detector_output.confidence)
    confidence_values = [detector_output.confidence]
    probability_values = [baseline_probability]
    labels = [detector_output.label]
    samples = [
        {
            "name": "baseline",
            "label": detector_output.label,
            "confidence": round(detector_output.confidence, 4),
            "attack_probability": round(baseline_probability, 4),
        }
    ]

    for variant_name, variant in generate_perturbation_variants(detector_snapshot):
        output = predictor.predict_from_features(variant, context=event)
        attack_probability = detector_attack_probability(output.label, output.confidence)
        confidence_values.append(output.confidence)
        probability_values.append(attack_probability)
        labels.append(output.label)
        samples.append(
            {
                "name": variant_name,
                "label": output.label,
                "confidence": round(output.confidence, 4),
                "attack_probability": round(attack_probability, 4),
            }
        )

    confidence_array = np.asarray(confidence_values, dtype=np.float32)
    probability_array = np.asarray(probability_values, dtype=np.float32)
    consistency = sum(label == detector_output.label for label in labels) / len(labels)

    return PerturbationSummary(
        mean_confidence=float(np.mean(confidence_array)),
        min_confidence=float(np.min(confidence_array)),
        max_confidence=float(np.max(confidence_array)),
        std_confidence=float(np.std(confidence_array)),
        confidence_drop=float(max(detector_output.confidence - float(np.min(confidence_array)), 0.0)),
        variance=float(np.var(probability_array)),
        label_consistency_ratio=float(consistency),
        samples=samples,
    )


def generate_perturbation_variants(detector_snapshot: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Generate small numeric perturbations for stability analysis."""

    variants: list[tuple[str, dict[str, Any]]] = []
    recipes = [
        ("lower-rate", {"packets_per_second": 0.94, "bytes_per_second": 0.95}),
        ("higher-rate", {"packets_per_second": 1.06, "bytes_per_second": 1.05}),
        ("shorter-duration", {"duration": 0.92, "forward_packets": 0.95, "backward_packets": 0.95}),
        ("longer-duration", {"duration": 1.08, "forward_packets": 1.04, "backward_packets": 1.04}),
        ("byte-balance-shift", {"forward_bytes": 1.08, "backward_bytes": 0.93}),
        ("packet-balance-shift", {"forward_packets": 1.07, "backward_packets": 0.94}),
    ]

    for name, multipliers in recipes:
        variant = dict(detector_snapshot)
        for field, multiplier in multipliers.items():
            variant[field] = max(_safe_float(variant.get(field)) * multiplier, 0.0)
        variants.append((name, variant))

    return variants


def synthesize_event_from_snapshot(
    snapshot: dict[str, Any],
    *,
    event_id: str,
    title: str,
    source: str,
) -> dict[str, Any]:
    """Build an event-like payload from canonical detector features for verifier training."""

    duration = max(_safe_float(snapshot.get("duration")), 0.1)
    forward_packets = max(_safe_float(snapshot.get("forward_packets")), 0.0)
    backward_packets = max(_safe_float(snapshot.get("backward_packets")), 0.0)
    forward_bytes = max(_safe_float(snapshot.get("forward_bytes")), 0.0)
    backward_bytes = max(_safe_float(snapshot.get("backward_bytes")), 0.0)
    packets_per_second = max(_safe_float(snapshot.get("packets_per_second")), 0.0)
    bytes_per_second = max(_safe_float(snapshot.get("bytes_per_second")), 0.0)
    total_bytes_kb = (forward_bytes + backward_bytes) / 1024.0
    destination_port = int(_safe_float(snapshot.get("destination_port")))
    protocol = str(snapshot.get("protocol", "UNKNOWN")).upper()

    anomaly_score = _clamp01(
        0.18
        + min(math.log1p(packets_per_second) / 14.0, 0.28)
        + min(math.log1p(bytes_per_second) / 15.0, 0.22)
        + (0.12 if destination_port in {22, 23, 3389} else 0.0)
        + (0.06 if protocol == "ICMP" else 0.0)
    )
    context_risk_score = _clamp01(
        0.14
        + (0.30 if destination_port in {22, 23, 3389} else 0.0)
        + (0.22 if packets_per_second > 550 else 0.0)
        + (0.16 if bytes_per_second > 250000 else 0.0)
    )
    known_bad_source = destination_port in {23, 3389} or packets_per_second > 850
    repeated_attempts = packets_per_second > 420 or forward_packets + backward_packets > 3500
    failed_logins = 7 if destination_port in {22, 23, 3389} and repeated_attempts else 0

    return {
        "id": event_id,
        "title": title,
        "description": "Verifier training sample generated from harmonized network-flow features.",
        "source_ip": "10.0.0.10",
        "destination_ip": "192.168.1.20",
        "source_port": int(_safe_float(snapshot.get("source_port"))),
        "destination_port": destination_port,
        "protocol": protocol,
        "bytes_transferred_kb": round(total_bytes_kb, 4),
        "duration_seconds": round(duration, 6),
        "packets_per_second": round(packets_per_second, 4),
        "failed_logins": failed_logins,
        "anomaly_score": round(anomaly_score, 4),
        "context_risk_score": round(context_risk_score, 4),
        "known_bad_source": known_bad_source,
        "off_hours_activity": bytes_per_second > 260000 or protocol == "ICMP",
        "repeated_attempts": repeated_attempts,
        "sample_source": source,
        "captured_at": "2026-01-01T00:00:00+00:00",
        "tags": ["training-generated"],
    }


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp01(value: float) -> float:
    return float(max(0.0, min(1.0, value)))
