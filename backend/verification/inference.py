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
        return str(self.bundle.metadata.get("model_version", "verifier-ensemble-mlp-v2"))

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
        uncertainty = self._estimate_uncertainty(features.vector)
        importance = self._compute_feature_importance(features.vector)

        final_status = self._decide_status(
            is_threat=detector_output.label != "Benign",
            probability=probability,
            uncertainty=uncertainty,
        )
        is_verified = final_status != SUSPICIOUS_STATUS

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
            probability=probability,
            is_verified=is_verified,
            final_status=final_status,
            feature_bundle=features,
            uncertainty=uncertainty,
            importance=importance,
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

    # ── core decision: pure model, no rule-based gates ────────────────────────

    def _decide_status(
        self,
        *,
        is_threat: bool,
        probability: float,
        uncertainty: dict[str, float],
    ) -> str:
        """Status is determined solely by the ensemble MLP + MC uncertainty.

        Rule-based gates removed: the trained model already learned these
        boundaries from data. Separate thresholds for threat vs benign allow
        independent optimisation via Youden's J on each decision direction.
        """
        if uncertainty.get("uncertain", False):
            return SUSPICIOUS_STATUS

        threshold = self._threat_threshold if is_threat else self._benign_threshold
        if probability >= threshold:
            return VERIFIED_THREAT_STATUS if is_threat else BENIGN_STATUS
        return SUSPICIOUS_STATUS

    # ── threshold properties ──────────────────────────────────────────────────

    @property
    def _threshold(self) -> float:
        return float(self.bundle.threshold) if self.bundle else 0.50

    @property
    def _threat_threshold(self) -> float:
        return float(self.bundle.threat_threshold) if self.bundle else self._threshold

    @property
    def _benign_threshold(self) -> float:
        return float(self.bundle.benign_threshold) if self.bundle else self._threshold

    # ── prediction helpers ────────────────────────────────────────────────────

    def _predict_probability(self, feature_map: dict[str, float], vector: list[float]) -> float:
        if self.bundle is not None:
            return self.bundle.predict_probability(vector)

        # Heuristic fallback when model artifact is absent.
        stability_proxy = 1.0 - min(feature_map["perturbation_confidence_drop"] * 2.0, 1.0)
        if feature_map["detector_is_threat"] >= 0.5:
            return float(max(0.0, min(1.0,
                feature_map["detector_confidence"] * 0.24
                + feature_map["detector_stability_score"] * 0.16
                + feature_map["context_consistency_score"] * 0.18
                + feature_map["cross_evidence_score"] * 0.18
                + feature_map["label_consistency_ratio"] * 0.16
                + stability_proxy * 0.08
            )))
        return float(max(0.0, min(1.0,
            feature_map["detector_confidence"] * 0.30
            + feature_map["context_consistency_score"] * 0.20
            + (1.0 - feature_map["cross_evidence_score"]) * 0.18
            + feature_map["label_consistency_ratio"] * 0.18
            + stability_proxy * 0.14
        )))

    def _estimate_uncertainty(self, vector: list[float]) -> dict[str, float]:
        if self.bundle is None:
            return {"mean": 0.5, "std": 0.0, "min": 0.5, "max": 0.5, "uncertain": False}
        return self.bundle.predict_with_uncertainty(vector, n_samples=10)

    def _compute_feature_importance(self, vector: list[float]) -> dict[str, float]:
        if self.bundle is None:
            return {}
        try:
            return self.bundle.feature_importance(vector, steps=15)
        except Exception:
            return {}

    # ── response building ─────────────────────────────────────────────────────

    def _verification_details(
        self,
        *,
        event: dict[str, Any],
        detector_output: PredictionOutput,
        probability: float,
        is_verified: bool,
        final_status: str,
        feature_bundle,
        uncertainty: dict[str, float],
        importance: dict[str, float],
    ) -> dict[str, Any]:
        is_threat = detector_output.label != "Benign"
        threshold = self._threat_threshold if is_threat else self._benign_threshold

        if final_status == BENIGN_STATUS:
            summary = "Ensemble verifier confirms benign — probability above benign threshold with low uncertainty."
        elif final_status == VERIFIED_THREAT_STATUS:
            summary = "Ensemble verifier confirms threat — probability above threat threshold with low uncertainty."
        else:
            reason = "high model uncertainty" if uncertainty.get("uncertain") else "probability below threshold"
            summary = f"Detector output not confirmed by ensemble verifier ({reason})."

        top_features = list(importance.items())[:5] if importance else []

        ensemble_members = len(self.bundle.models) if self.bundle else 0
        label_consistency = feature_bundle.perturbation.label_consistency_ratio
        confidence_drop = feature_bundle.perturbation.confidence_drop
        std_confidence = feature_bundle.perturbation.std_confidence
        pert_passed = label_consistency >= 0.74 and confidence_drop <= 0.18
        alignment = feature_bundle.support_alignment_score
        uncertainty_score = max(0.0, min(1.0, 1.0 - uncertainty.get("std", 0.0) * 5.0))
        mc_samples = 10

        checks = [
            {
                "key": "neural_ensemble",
                "title": "Neural Ensemble Decision",
                "description": (
                    f"An ensemble of {ensemble_members} MLP models voted on the "
                    "trustworthiness of the Stage-1 detector output. "
                    "Score is the Platt-calibrated ensemble probability."
                ),
                "passed": probability >= threshold,
                "score": round(probability, 4),
                "weight": 0.35,
                "evidence": [
                    f"Probability: {round(probability, 4)}",
                    f"Threshold ({'threat' if is_threat else 'benign'}): {round(threshold, 4)}",
                    "Decision: above threshold → verified" if probability >= threshold
                    else "Decision: below threshold → not verified",
                ],
            },
            {
                "key": "mc_uncertainty",
                "title": "MC Dropout Uncertainty",
                "description": (
                    f"Monte Carlo dropout runs {mc_samples} forward passes with active "
                    "dropout to estimate epistemic uncertainty. "
                    "High std (> 0.12) routes to analyst review."
                ),
                "passed": not uncertainty.get("uncertain", False),
                "score": round(uncertainty_score, 4),
                "weight": 0.20,
                "evidence": [
                    f"Mean probability: {round(uncertainty.get('mean', probability), 4)}",
                    f"Std deviation: {round(uncertainty.get('std', 0.0), 4)}",
                    f"Uncertain: {'yes — routed to analyst' if uncertainty.get('uncertain') else 'no'}",
                    f"MC passes: {mc_samples} × {ensemble_members} models (fast-path)",
                ],
            },
            {
                "key": "context_support",
                "title": "Context & Evidence Support",
                "description": (
                    "Context consistency and cross-evidence scores measure how well "
                    "event behavioral signals (port, failed logins, timing, repeated "
                    "attempts) align with the detector verdict."
                ),
                "passed": alignment >= 0.50,
                "score": round(alignment, 4),
                "weight": 0.20,
                "evidence": [
                    f"Context consistency: {round(feature_bundle.context_consistency_score, 4)}",
                    f"Cross-evidence score: {round(feature_bundle.cross_evidence_score, 4)}",
                    f"Support alignment: {round(alignment, 4)}",
                ],
            },
            {
                "key": "perturbation_stability",
                "title": "Perturbation Stability",
                "description": (
                    "The detector was re-run on 6 slightly modified flow variants "
                    "(rate ±6%, duration ±8%, byte/packet balance shifts). "
                    "High label consistency and low confidence drop confirm robustness."
                ),
                "passed": pert_passed,
                "score": round(label_consistency, 4),
                "weight": 0.15,
                "evidence": [
                    f"Label consistency: {round(label_consistency * 100):.0f}%",
                    f"Confidence drop: {round(confidence_drop, 4)}",
                    f"Confidence std across variants: {round(std_confidence, 4)}",
                    "Stability: passed (consistency ≥ 74%, drop ≤ 0.18)"
                    if pert_passed else "Stability: failed",
                ],
            },
            {
                "key": "feature_attribution",
                "title": "Integrated Gradients Attribution",
                "description": (
                    "Integrated Gradients computes per-feature attributions against a "
                    "background baseline, revealing which signals drove the verifier's decision."
                ),
                "passed": bool(top_features),
                "score": 1.0 if top_features else 0.0,
                "weight": 0.10,
                "evidence": [
                    f"{feat}: {'+' if attr >= 0 else ''}{round(attr, 4)}"
                    for feat, attr in top_features
                ],
            },
        ]

        return {
            "summary": summary,
            "checks": checks,
            "model_decision": {
                "probability": round(probability, 4),
                "threshold_used": round(threshold, 4),
                "threshold_type": "threat" if is_threat else "benign",
                "above_threshold": probability >= threshold,
            },
            "uncertainty": {
                "mean_probability": round(uncertainty.get("mean", probability), 4),
                "std_deviation": round(uncertainty.get("std", 0.0), 4),
                "is_uncertain": uncertainty.get("uncertain", False),
                "mc_samples": 10,
                "ensemble_members": len(self.bundle.models) if self.bundle else 0,
            },
            "feature_importance": {
                "top_5": [{"feature": k, "attribution": v} for k, v in top_features],
                "method": "integrated_gradients",
            },
            "support_scores": {
                "context_consistency_score": round(feature_bundle.context_consistency_score, 4),
                "cross_evidence_score": round(feature_bundle.cross_evidence_score, 4),
                "support_alignment_score": round(feature_bundle.support_alignment_score, 4),
            },
            "perturbation_analysis": asdict(feature_bundle.perturbation),
            "event_context": {
                "anomaly_score": round(float(event.get("anomaly_score", 0.0)), 4),
                "context_risk_score": round(float(event.get("context_risk_score", 0.0)), 4),
                "known_bad_source": bool(event.get("known_bad_source")),
                "off_hours_activity": bool(event.get("off_hours_activity")),
                "repeated_attempts": bool(event.get("repeated_attempts")),
            },
            "model_type": "ensemble-tabular-mlp" if self.bundle is not None else "heuristic-fallback",
            "model_available": self.bundle is not None,
            "is_verified_by_model": is_verified,
        }

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
