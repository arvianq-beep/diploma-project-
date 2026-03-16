import 'package:diploma_application_ml/domain/models/verification_check.dart';

class VerificationResult {
  final List<VerificationCheck> checks;
  final bool passed;
  final double verificationScore;
  final List<String> explanationNotes;
  final String summary;

  const VerificationResult({
    required this.checks,
    required this.passed,
    required this.verificationScore,
    required this.explanationNotes,
    required this.summary,
  });
}
