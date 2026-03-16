import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/verification_check.dart';

class FinalDecision {
  final String rawAiLabel;
  final double rawConfidence;
  final List<VerificationCheck> verificationChecks;
  final FinalDecisionStatus status;
  final String explanation;
  final DateTime timestamp;
  final String recommendedAnalystAction;

  const FinalDecision({
    required this.rawAiLabel,
    required this.rawConfidence,
    required this.verificationChecks,
    required this.status,
    required this.explanation,
    required this.timestamp,
    required this.recommendedAnalystAction,
  });
}
