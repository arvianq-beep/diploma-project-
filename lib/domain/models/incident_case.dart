import 'package:diploma_application_ml/domain/models/analysis_result.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/final_decision.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';
import 'package:diploma_application_ml/domain/models/verification_result.dart';

class IncidentCase {
  final ThreatEvent event;
  final AnalysisResult analysis;
  final VerificationResult verification;
  final FinalDecision finalDecision;
  final AnalystReview analystReview;

  const IncidentCase({
    required this.event,
    required this.analysis,
    required this.verification,
    required this.finalDecision,
    required this.analystReview,
  });

  IncidentCase copyWith({
    ThreatEvent? event,
    AnalysisResult? analysis,
    VerificationResult? verification,
    FinalDecision? finalDecision,
    AnalystReview? analystReview,
  }) {
    return IncidentCase(
      event: event ?? this.event,
      analysis: analysis ?? this.analysis,
      verification: verification ?? this.verification,
      finalDecision: finalDecision ?? this.finalDecision,
      analystReview: analystReview ?? this.analystReview,
    );
  }
}
