from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ml.inference import MLPredictor, PredictionOutput

from .features import build_verification_features
from .model import load_artifacts
from .schema import BENIGN_STATUS, SUSPICIOUS_STATUS, VERIFIED_THREAT_STATUS


@dataclass(slots=True)
class VerificationDecision:
    """Final Stage 2 verifier result returned by the backend pipeline."""

    threat_type: str
    is_threat: bool
    ai_confidence: float
    detector_label: str
    detector_details: dict[str, Any]
    verification_confidence: float
    is_verified: bool
    verification_details: dict[str, Any]
    final_decision_status: str
    recommended_action: str
    model_available: bool
    detector_model_version: str
    verifier_model_version: str
    feature_snapshot: dict[str, Any]


class SecureDecisionVerificationService:
    """Backend-side Secure Decision Verification orchestration service."""

    def __init__(self, predictor: MLPredictor):
        self.predictor = predictor
        self.bundle = load_artifacts()

    @property
    def available(self) -> bool:
        return self.bundle is not None

    @property
    def model_version(self) -> str:
        if self.bundle is None:
            return "verifier-heuristic-fallback"
        return str(self.bundle.metadata.get("model_version", "verifier-tabular-mlp-v1"))

    @property
    def metadata(self) -> dict[str, Any]:
        return self.bundle.metadata if self.bundle is not None else {}

    @property
    def metrics(self) -> dict[str, Any]:
        return self.bundle.metrics if self.bundle is not None else {}

    def evaluate(self, event: dict[str, Any], detector_output: PredictionOutput) -> VerificationDecision:
        """Run Stage 2 verification using the detector output and event features."""

        features = build_verification_features(
            predictor=self.predictor,
            event=event,
            detector_output=detector_output,
        )
        probability = self._predict_probability(features.feature_map, features.vector)
        is_verified = probability >= self._threshold
        final_status = self._final_status(
            detector_output=detector_output,
            verification_confidence=probability,
            feature_bundle=features,
        )
        detector_details = {
            "reasoning": detector_output.reasoning,
            "alternative_hypothesis": detector_output.alternative_hypothesis,
            "stability_score": round(detector_output.stability_score, 4),
            "triggered_indicators": detector_output.triggered_indicators,
            "triggered_indicators_count": len(detector_output.triggered_indicators),
        }
        verification_details = self._verification_details(
            event=event,
            detector_output=detector_output,
            verification_confidence=probability,
            is_verified=is_verified,
            final_status=final_status,
            feature_bundle=features,
        )

        return VerificationDecision(
            threat_type=detector_output.label if detector_output.label != "Benign" else BENIGN_STATUS,
            is_threat=detector_output.label != "Benign",
            ai_confidence=round(detector_output.confidence, 4),
            detector_label=detector_output.label,
            detector_details=detector_details,
            verification_confidence=round(probability, 4),
            is_verified=is_verified,
            verification_details=verification_details,
            final_decision_status=final_status,
            recommended_action=self._recommended_action(final_status),
            model_available=self.predictor.available,
            detector_model_version=detector_output.model_version,
            verifier_model_version=self.model_version,
            feature_snapshot={
                "event": self._event_snapshot(event),
                "detector": detector_output.feature_snapshot,
                "verifier_input": features.feature_map,
            },
        )

    @property
    def _threshold(self) -> float:
        if self.bundle is None:
            return 0.58
        return float(self.bundle.threshold)

    def _predict_probability(self, feature_map: dict[str, float], vector: list[float]) -> float:
        if self.bundle is not None:
            return self.bundle.predict_probability(vector)

        stability_proxy = 1.0 - min(feature_map["perturbation_confidence_drop"] * 2.0, 1.0)
        probability = (
            feature_map["detector_confidence"] * 0.24
            + feature_map["detector_stability_score"] * 0.16
            + feature_map["context_consistency_score"] * 0.18
            + feature_map["cross_evidence_score"] * 0.18
            + feature_map["label_consistency_ratio"] * 0.16
            + stability_proxy * 0.08
        )
        if feature_map["detector_is_threat"] < 0.5:
            probability = (
                feature_map["detector_confidence"] * 0.30
                + feature_map["context_consistency_score"] * 0.20
                + (1.0 - feature_map["cross_evidence_score"]) * 0.18
                + feature_map["label_consistency_ratio"] * 0.18
                + stability_proxy * 0.14
            )
        return float(max(0.0, min(1.0, probability)))

    def _final_status(
        self,
        *,
        detector_output: PredictionOutput,
        verification_confidence: float,
        feature_bundle,
    ) -> str:
        unstable = (
            detector_output.stability_score < 0.55
            or feature_bundle.perturbation.label_consistency_ratio < 0.72
            or feature_bundle.perturbation.confidence_drop > 0.18
            or feature_bundle.perturbation.variance > 0.09
        )

        if detector_output.label == "Benign":
            benign_supported = (
                verification_confidence >= self._threshold
                and feature_bundle.context_consistency_score >= 0.52
                and feature_bundle.cross_evidence_score <= 0.46
                and feature_bundle.perturbation.label_consistency_ratio >= 0.78
                and not unstable
            )
            return BENIGN_STATUS if benign_supported else SUSPICIOUS_STATUS

        threat_supported = (
            verification_confidence >= max(self._threshold, 0.62)
            and detector_output.confidence >= 0.60
            and feature_bundle.context_consistency_score >= 0.48
            and feature_bundle.cross_evidence_score >= 0.54
            and feature_bundle.perturbation.label_consistency_ratio >= 0.72
            and not unstable
        )
        return VERIFIED_THREAT_STATUS if threat_supported else SUSPICIOUS_STATUS

    def _verification_details(
        self,
        *,
        event: dict[str, Any],
        detector_output: PredictionOutput,
        verification_confidence: float,
        is_verified: bool,
        final_status: str,
        feature_bundle,
    ) -> dict[str, Any]:
        checks = self._build_checks(
            detector_output=detector_output,
            verification_confidence=verification_confidence,
            feature_bundle=feature_bundle,
        )
        failed_titles = [check["title"] for check in checks if not check["passed"]]
        if final_status == BENIGN_STATUS:
            summary = "The backend verifier supports the benign interpretation, so the final operational status remains Benign."
        elif final_status == VERIFIED_THREAT_STATUS:
            summary = "The backend verifier confirms the detector threat output with stable, context-supported evidence, so the event is promoted to Verified Threat."
        else:
            failed_text = ", ".join(failed_titles) if failed_titles else "verification disagreement"
            summary = (
                f"The detector output was not confirmed strongly enough by the verifier. "
                f"The event is marked Suspicious because of {failed_text}."
            )

        return {
            "summary": summary,
            "checks": checks,
            "support_scores": {
                "context_consistency_score": round(feature_bundle.context_consistency_score, 4),
                "cross_evidence_score": round(feature_bundle.cross_evidence_score, 4),
                "support_alignment_score": round(feature_bundle.support_alignment_score, 4),
            },
            "perturbation_analysis": asdict(feature_bundle.perturbation),
            "threshold_used": round(self._threshold, 4),
            "event_context": {
                "anomaly_score": round(float(event.get("anomaly_score", 0.0)), 4),
                "context_risk_score": round(float(event.get("context_risk_score", 0.0)), 4),
                "known_bad_source": bool(event.get("known_bad_source")),
                "off_hours_activity": bool(event.get("off_hours_activity")),
                "repeated_attempts": bool(event.get("repeated_attempts")),
            },
            "model_type": "tabular-mlp" if self.bundle is not None else "heuristic-fallback",
            "model_available": self.bundle is not None,
            "is_verified_by_model": is_verified,
        }

    def _build_checks(
        self,
        *,
        detector_output: PredictionOutput,
        verification_confidence: float,
        feature_bundle,
    ) -> list[dict[str, Any]]:
        perturbation = feature_bundle.perturbation
        is_benign = detector_output.label == "Benign"
        threat_evidence_pass = feature_bundle.cross_evidence_score <= 0.46 if is_benign else feature_bundle.cross_evidence_score >= 0.54

        return [
            {
                "key": "verification_model",
                "title": "Neural verifier confidence",
                "description": "Stage 2 MLP confidence that the detector output is trustworthy enough for operational use.",
                "passed": verification_confidence >= self._threshold,
                "score": round(verification_confidence, 4),
                "weight": 0.30,
                "evidence": [
                    f"Verifier confidence: {verification_confidence:.2f}",
                    f"Decision threshold: {self._threshold:.2f}",
                    f"Verifier model version: {self.model_version}",
                ],
            },
            {
                "key": "detector_stability",
                "title": "Detector stability under perturbation",
                "description": "Checks whether Stage 1 remains stable when nearby numeric features are perturbed.",
                "passed": detector_output.stability_score >= 0.55 and perturbation.label_consistency_ratio >= 0.72 and perturbation.confidence_drop <= 0.18,
                "score": round((detector_output.stability_score + perturbation.label_consistency_ratio + (1.0 - min(perturbation.confidence_drop, 1.0))) / 3.0, 4),
                "weight": 0.24,
                "evidence": [
                    f"Detector stability score: {detector_output.stability_score:.2f}",
                    f"Label consistency ratio: {perturbation.label_consistency_ratio:.2f}",
                    f"Confidence drop under perturbation: {perturbation.confidence_drop:.2f}",
                ],
            },
            {
                "key": "context_consistency",
                "title": "Context consistency support",
                "description": "Measures whether anomaly/context evidence supports the detector interpretation.",
                "passed": feature_bundle.context_consistency_score >= 0.52 if is_benign else feature_bundle.context_consistency_score >= 0.48,
                "score": round(feature_bundle.context_consistency_score, 4),
                "weight": 0.18,
                "evidence": [
                    f"Context consistency score: {feature_bundle.context_consistency_score:.2f}",
                    "Benign decisions require low contextual risk; threat decisions require supportive anomaly and context signals.",
                ],
            },
            {
                "key": "cross_evidence",
                "title": "Cross-evidence support",
                "description": "Combines deterministic evidence such as risky ports, failed logins, known-bad context, and triggered indicators.",
                "passed": threat_evidence_pass,
                "score": round(1.0 - feature_bundle.cross_evidence_score if is_benign else feature_bundle.cross_evidence_score, 4),
                "weight": 0.16,
                "evidence": [
                    f"Cross-evidence score: {feature_bundle.cross_evidence_score:.2f}",
                    "Threat detections require high cross-evidence support; benign detections require low threat evidence.",
                ],
            },
            {
                "key": "support_alignment",
                "title": "Overall support alignment",
                "description": "Summarizes whether detector confidence, context, and perturbation evidence point in the same direction.",
                "passed": feature_bundle.support_alignment_score >= 0.55,
                "score": round(feature_bundle.support_alignment_score, 4),
                "weight": 0.12,
                "evidence": [
                    f"Support alignment score: {feature_bundle.support_alignment_score:.2f}",
                    f"Triggered indicators: {len(detector_output.triggered_indicators)}",
                ],
            },
        ]

    @staticmethod
    def _event_snapshot(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "protocol": event.get("protocol"),
            "source_port": event.get("source_port"),
            "destination_port": event.get("destination_port"),
            "duration_seconds": event.get("duration_seconds"),
            "bytes_transferred_kb": event.get("bytes_transferred_kb"),
            "packets_per_second": event.get("packets_per_second"),
            "failed_logins": event.get("failed_logins"),
            "anomaly_score": event.get("anomaly_score"),
            "context_risk_score": event.get("context_risk_score"),
            "known_bad_source": event.get("known_bad_source"),
            "off_hours_activity": event.get("off_hours_activity"),
            "repeated_attempts": event.get("repeated_attempts"),
        }

    @staticmethod
    def _recommended_action(final_status: str) -> str:
        if final_status == BENIGN_STATUS:
            return "Archive event and continue passive monitoring."
        if final_status == VERIFIED_THREAT_STATUS:
            return "Escalate to incident response and isolate the affected asset."
        return "Route to analyst review with supporting detector and verifier evidence."
