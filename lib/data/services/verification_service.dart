import 'package:diploma_application_ml/domain/models/analysis_result.dart';
import 'package:diploma_application_ml/domain/models/final_decision.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';
import 'package:diploma_application_ml/domain/models/verification_check.dart';
import 'package:diploma_application_ml/domain/models/verification_result.dart';

class VerificationOutcome {
  final VerificationResult verification;
  final FinalDecision decision;

  const VerificationOutcome({
    required this.verification,
    required this.decision,
  });
}

class VerificationService {
  const VerificationService();

  VerificationOutcome verify({
    required ThreatEvent event,
    required AnalysisResult analysis,
  }) {
    final checks = <VerificationCheck>[
      _confidenceCheck(analysis),
      _stabilityCheck(analysis),
      _contextCheck(event, analysis),
      _crossEvidenceCheck(event, analysis),
      _explainabilityCheck(analysis),
    ];

    final totalWeight = checks.fold<double>(
      0,
      (sum, item) => sum + item.weight,
    );
    final weightedScore = checks.fold<double>(
      0,
      (sum, item) => sum + (item.score * item.weight),
    );
    final verificationScore = weightedScore / totalWeight;
    final criticalChecksPassed = checks
        .where(
          (check) =>
              check.key == 'confidence' ||
              check.key == 'stability' ||
              check.key == 'cross_evidence',
        )
        .every((check) => check.passed);

    final status = _finalStatus(
      rawLabel: analysis.rawAiLabel,
      rawConfidence: analysis.rawConfidence,
      verificationScore: verificationScore,
      criticalChecksPassed: criticalChecksPassed,
    );

    final summary = _buildSummary(status, analysis, checks);
    final explanationNotes = [
      'Raw AI output is never used directly as the final verdict.',
      'Verification score is derived from weighted confidence, stability, context and evidence checks.',
      'Analyst action is tied to the verified status rather than the raw model label.',
    ];

    final verification = VerificationResult(
      checks: checks,
      passed: status != FinalDecisionStatus.suspicious,
      verificationScore: verificationScore,
      explanationNotes: explanationNotes,
      summary: summary,
    );

    final decision = FinalDecision(
      rawAiLabel: analysis.rawAiLabel,
      rawConfidence: analysis.rawConfidence,
      verificationChecks: checks,
      status: status,
      explanation: summary,
      timestamp: DateTime.now(),
      recommendedAnalystAction: status.analystAction,
    );

    return VerificationOutcome(verification: verification, decision: decision);
  }

  VerificationCheck _confidenceCheck(AnalysisResult analysis) {
    final threshold = analysis.rawAiLabel == 'Benign' ? 0.62 : 0.74;
    final passed = analysis.rawConfidence >= threshold;
    return VerificationCheck(
      key: 'confidence',
      title: 'Confidence threshold check',
      description:
          'Confirms that the raw model score is strong enough for the predicted class.',
      passed: passed,
      score: analysis.rawConfidence,
      weight: 0.22,
      evidence: [
        'Predicted label: ${analysis.rawAiLabel}',
        'Observed confidence: ${analysis.rawConfidence.toStringAsFixed(2)}',
        'Required threshold: ${threshold.toStringAsFixed(2)}',
      ],
    );
  }

  VerificationCheck _stabilityCheck(AnalysisResult analysis) {
    final passed = analysis.stabilityScore >= 0.66;
    return VerificationCheck(
      key: 'stability',
      title: 'Stability and consistency check',
      description:
          'Estimates whether the prediction stays stable across adjacent feature perturbations.',
      passed: passed,
      score: analysis.stabilityScore,
      weight: 0.22,
      evidence: [
        'Stability score: ${analysis.stabilityScore.toStringAsFixed(2)}',
        'Alternative hypothesis: ${analysis.alternativeHypothesis}',
      ],
    );
  }

  VerificationCheck _contextCheck(ThreatEvent event, AnalysisResult analysis) {
    final score = analysis.rawAiLabel == 'Benign'
        ? (1 - ((event.contextRiskScore + event.anomalyScore) / 2))
        : ((event.contextRiskScore * 0.6) + (event.anomalyScore * 0.4));
    final passed = score >= (analysis.rawAiLabel == 'Benign' ? 0.60 : 0.58);
    return VerificationCheck(
      key: 'context',
      title: 'Anomaly and context cross-check',
      description:
          'Checks whether the behavioral context supports the raw model hypothesis.',
      passed: passed,
      score: score,
      weight: 0.18,
      evidence: [
        'Anomaly score: ${event.anomalyScore.toStringAsFixed(2)}',
        'Context risk: ${event.contextRiskScore.toStringAsFixed(2)}',
        if (event.offHoursActivity) 'Observed outside normal business window.',
      ],
    );
  }

  VerificationCheck _crossEvidenceCheck(
    ThreatEvent event,
    AnalysisResult analysis,
  ) {
    var score = 0.18;
    if (event.knownBadSource) score += 0.22;
    if (event.failedLogins >= 6) score += 0.22;
    if (event.bytesTransferredKb >= 10000) score += 0.18;
    if (event.repeatedAttempts) score += 0.14;
    if (analysis.triggeredIndicators.isNotEmpty) score += 0.12;
    if (event.tags.contains('diagnostics-window')) score -= 0.18;

    final normalizedScore = score.clamp(0.0, 1.0);
    final benignPass =
        analysis.rawAiLabel == 'Benign' && normalizedScore <= 0.44;
    final threatPass =
        analysis.rawAiLabel != 'Benign' && normalizedScore >= 0.58;

    return VerificationCheck(
      key: 'cross_evidence',
      title: 'Rule-based cross-evidence validation',
      description:
          'Combines deterministic security rules with contextual indicators to validate the AI output.',
      passed: benignPass || threatPass,
      score: analysis.rawAiLabel == 'Benign'
          ? (1 - normalizedScore)
          : normalizedScore,
      weight: 0.24,
      evidence: [
        'Cross-evidence score: ${normalizedScore.toStringAsFixed(2)}',
        if (event.knownBadSource) 'Threat intelligence match present.',
        if (event.failedLogins >= 6) 'Authentication abuse rule triggered.',
        if (event.repeatedAttempts) 'Repeated-attempt heuristic triggered.',
        if (event.tags.contains('diagnostics-window'))
          'Diagnostic window reduces certainty.',
      ],
    );
  }

  VerificationCheck _explainabilityCheck(AnalysisResult analysis) {
    final score = analysis.triggeredIndicators.isNotEmpty ? 0.92 : 0.40;
    return VerificationCheck(
      key: 'explainability',
      title: 'Explainability support check',
      description:
          'Ensures the final verdict can be justified with interpretable indicators.',
      passed: score >= 0.80,
      score: score,
      weight: 0.14,
      evidence: analysis.triggeredIndicators,
    );
  }

  FinalDecisionStatus _finalStatus({
    required String rawLabel,
    required double rawConfidence,
    required double verificationScore,
    required bool criticalChecksPassed,
  }) {
    if (rawLabel == 'Benign' &&
        rawConfidence >= 0.62 &&
        verificationScore >= 0.67 &&
        criticalChecksPassed) {
      return FinalDecisionStatus.benign;
    }

    if (rawLabel != 'Benign' &&
        rawConfidence >= 0.74 &&
        verificationScore >= 0.76 &&
        criticalChecksPassed) {
      return FinalDecisionStatus.verifiedThreat;
    }

    return FinalDecisionStatus.suspicious;
  }

  String _buildSummary(
    FinalDecisionStatus status,
    AnalysisResult analysis,
    List<VerificationCheck> checks,
  ) {
    final failedChecks = checks
        .where((item) => !item.passed)
        .map((item) => item.title);

    switch (status) {
      case FinalDecisionStatus.benign:
        return 'The raw model predicted benign traffic and the verification layer confirmed that the confidence, context and rule evidence all remain within a safe operating range.';
      case FinalDecisionStatus.verifiedThreat:
        return 'The raw AI prediction of ${analysis.rawAiLabel} is supported by multiple verification checks, so the system upgrades the event to a verified threat rather than trusting confidence alone.';
      case FinalDecisionStatus.suspicious:
        final failed = failedChecks.isEmpty
            ? 'verification disagreement'
            : failedChecks.join(', ');
        return 'The raw AI output points to ${analysis.rawAiLabel}, but the verification layer found unresolved gaps in $failed. The event is therefore marked suspicious and routed to an analyst.';
    }
  }
}
