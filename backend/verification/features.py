from __future__ import annotations

import math
from typing import Any

import numpy as np
import pandas as pd

from ml.inference import MLPredictor, PredictionOutput

from .schema import PerturbationSummary, VERIFIER_FEATURE_NAMES, VerificationFeatureBundle

# Perturbation recipes used by generate_perturbation_variants (per-row) and
# run_perturbation_analysis_batch.  Keeping them here ensures both paths are
# always identical.
PERTURBATION_RECIPES: tuple[tuple[str, dict[str, float]], ...] = (
    ("lower-rate",           {"flow_packets_per_s": 0.94, "flow_bytes_per_s": 0.95}),
    ("higher-rate",          {"flow_packets_per_s": 1.06, "flow_bytes_per_s": 1.05}),
    ("shorter-duration",     {"flow_duration": 0.92, "total_fwd_packets": 0.95, "total_bwd_packets": 0.95}),
    ("longer-duration",      {"flow_duration": 1.08, "total_fwd_packets": 1.04, "total_bwd_packets": 1.04}),
    ("byte-balance-shift",   {"total_length_fwd_packets": 1.08, "total_length_bwd_packets": 0.93}),
    ("packet-balance-shift", {"total_fwd_packets": 1.07, "total_bwd_packets": 0.94}),
)


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
        **raw_indicator_feature_map(event, detector_output),
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


def raw_indicator_feature_map(event: dict[str, Any], detector_output: PredictionOutput) -> dict[str, float]:
    """Individual binary indicator flags exposed as standalone MLP features.

    These mirror the rules inside cross_evidence_score but as separate inputs so
    the MLP can learn its own weights for each indicator rather than depending on
    the hardcoded coefficients in the aggregated score.
    """
    snapshot = detector_output.feature_snapshot
    destination_port = int(_safe_float(event.get("destination_port")))
    failed_logins = int(_safe_float(event.get("failed_logins")))
    packets_per_second = _safe_float(snapshot.get("flow_packets_per_s")) if snapshot else _safe_float(event.get("packets_per_second"))
    fwd_bytes = _safe_float(snapshot.get("total_length_fwd_packets", 0)) if snapshot else 0.0
    bwd_bytes = _safe_float(snapshot.get("total_length_bwd_packets", 0)) if snapshot else 0.0
    bytes_kb = (fwd_bytes + bwd_bytes) / 1024.0

    return {
        "indicator_risky_port": 1.0 if destination_port in {22, 23, 3389} else 0.0,
        "indicator_failed_logins_high": 1.0 if failed_logins >= 6 else 0.0,
        "indicator_high_pps": 1.0 if packets_per_second >= 550 else 0.0,
        "indicator_high_bytes": 1.0 if bytes_kb >= 9000 else 0.0,
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
    failed_logins = int(_safe_float(event.get("failed_logins")))
    indicators_count = len(detector_output.triggered_indicators)

    # Use canonical flow metrics from the detector snapshot.
    # feature_snapshot is always populated with all 77 FEATURE_SCHEMA keys by
    # _run_prediction before verification runs — if it is empty, that means the
    # caller skipped inference, which is a programming error.
    snapshot = detector_output.feature_snapshot
    if not snapshot:
        raise ValueError(
            "detector_output.feature_snapshot is empty. "
            "predict_from_features() or predict_from_event() must run before verification."
        )
    packets_per_second = _safe_float(snapshot.get("flow_packets_per_s"))
    fwd_bytes = _safe_float(snapshot.get("total_length_fwd_packets"))
    bwd_bytes = _safe_float(snapshot.get("total_length_bwd_packets"))
    bytes_kb = (fwd_bytes + bwd_bytes) / 1024.0

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
    """Generate small numeric perturbations for per-row stability analysis."""
    variants: list[tuple[str, dict[str, Any]]] = []
    for name, multipliers in PERTURBATION_RECIPES:
        variant = dict(detector_snapshot)
        for field, multiplier in multipliers.items():
            variant[field] = max(_safe_float(variant.get(field)) * multiplier, 0.0)
        variants.append((name, variant))
    return variants


def run_perturbation_analysis_batch(
    predictor: MLPredictor,
    snapshots: list[dict[str, Any]],
    baseline_outputs: list[PredictionOutput],
) -> list[PerturbationSummary]:
    """Batch perturbation analysis: one predict_proba call for all N × 6 variants.

    Replaces N sequential calls to run_perturbation_analysis(), each of which called
    predict_from_features() 6 times (6 × 6 = 36 predict_proba calls per row due to
    inner stability scoring).  This function issues a single call over the entire
    (N × 6, 77) stacked DataFrame.

    All statistics are identical to the per-row implementation:
      • confidence values use max(p, 1−p)  (how certain the model is, regardless of direction)
      • probability values use raw attack probability p  (for variance)
      • label consistency counts variants whose label matches the baseline
    """
    N = len(snapshots)
    if N == 0:
        return []

    n_variants = len(PERTURBATION_RECIPES)
    feature_order = predictor.feature_order

    # Build (N × n_variants, 77) DataFrame — outer loop = recipe, inner = row
    # so that reshape(n_variants, N).T gives (N, n_variants) correctly.
    variant_frames: list[pd.DataFrame] = []
    for _, recipe in PERTURBATION_RECIPES:
        rows: list[list[float]] = []
        for snap in snapshots:
            variant = dict(snap)
            for col, mul in recipe.items():
                variant[col] = max(_safe_float(variant.get(col)) * mul, 0.0)
            rows.append([_safe_float(variant.get(f, 0.0)) for f in feature_order])
        variant_frames.append(pd.DataFrame(rows, columns=feature_order))

    stacked = pd.concat(variant_frames, ignore_index=True)   # (N × n_variants, 77)

    if predictor.pipeline is not None:
        raw_variant_probs = predictor.pipeline.predict_proba(stacked)[:, 1]
    else:
        raw_variant_probs = predictor._raw_probs_batch(stacked)

    # reshape: (n_variants, N).T → (N, n_variants)
    variant_probs = raw_variant_probs.reshape(n_variants, N).T  # (N, n_variants)

    # ── vectorised aggregation ────────────────────────────────────────────────
    baseline_confs = np.array([o.confidence for o in baseline_outputs], dtype=np.float64)
    baseline_attack = np.array(
        [detector_attack_probability(o.label, o.confidence) for o in baseline_outputs],
        dtype=np.float64,
    )

    # confidence = max(p, 1−p) for each variant
    variant_confs = np.where(variant_probs >= 0.5, variant_probs, 1.0 - variant_probs)  # (N, n_variants)

    all_confs = np.hstack([baseline_confs[:, None], variant_confs])    # (N, n_variants+1)
    all_probs = np.hstack([baseline_attack[:, None], variant_probs])   # (N, n_variants+1)

    mean_confs = all_confs.mean(axis=1)
    min_confs  = all_confs.min(axis=1)
    max_confs  = all_confs.max(axis=1)
    std_confs  = all_confs.std(axis=1)
    conf_drops = np.maximum(baseline_confs - min_confs, 0.0)
    variances  = all_probs.var(axis=1)

    baseline_is_attack = (baseline_attack >= 0.5)[:, None]              # (N, 1) bool
    variant_is_attack  = variant_probs >= 0.5                            # (N, n_variants) bool
    all_is_attack = np.hstack([baseline_is_attack, variant_is_attack])  # (N, n_variants+1)
    consistency = (all_is_attack == baseline_is_attack).mean(axis=1)    # (N,)

    return [
        PerturbationSummary(
            mean_confidence=float(mean_confs[i]),
            min_confidence=float(min_confs[i]),
            max_confidence=float(max_confs[i]),
            std_confidence=float(std_confs[i]),
            confidence_drop=float(conf_drops[i]),
            variance=float(variances[i]),
            label_consistency_ratio=float(consistency[i]),
            samples=[],  # Not populated in batch mode (training does not need per-sample detail)
        )
        for i in range(N)
    ]


def synthesize_event_from_snapshot(
    snapshot: dict[str, Any],
    *,
    event_id: str,
    title: str,
    source: str,
) -> dict[str, Any]:
    """Build an event-like payload from canonical detector features for verifier training."""

    duration = max(_safe_float(snapshot.get("flow_duration")), 0.1)
    forward_packets = max(_safe_float(snapshot.get("total_fwd_packets")), 0.0)
    backward_packets = max(_safe_float(snapshot.get("total_bwd_packets")), 0.0)
    forward_bytes = max(_safe_float(snapshot.get("total_length_fwd_packets")), 0.0)
    backward_bytes = max(_safe_float(snapshot.get("total_length_bwd_packets")), 0.0)
    packets_per_second = max(_safe_float(snapshot.get("flow_packets_per_s")), 0.0)
    bytes_per_second = max(_safe_float(snapshot.get("flow_bytes_per_s")), 0.0)
    total_bytes_kb = (forward_bytes + backward_bytes) / 1024.0
    destination_port = int(_safe_float(snapshot.get("destination_port")))

    anomaly_score = _clamp01(
        0.18
        + min(math.log1p(packets_per_second) / 14.0, 0.28)
        + min(math.log1p(bytes_per_second) / 15.0, 0.22)
        + (0.12 if destination_port in {22, 23, 3389} else 0.0)
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
        "source_port": 0,
        "destination_port": destination_port,
        "protocol": "UNKNOWN",
        "bytes_transferred_kb": round(total_bytes_kb, 4),
        "duration_seconds": round(duration, 6),
        "packets_per_second": round(packets_per_second, 4),
        "failed_logins": failed_logins,
        "anomaly_score": round(anomaly_score, 4),
        "context_risk_score": round(context_risk_score, 4),
        "known_bad_source": known_bad_source,
        "off_hours_activity": bytes_per_second > 260000,
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
