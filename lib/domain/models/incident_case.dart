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
  /// Database row ID from reports.db — null for mock/offline incidents.
  final int? reportId;

  const IncidentCase({
    required this.event,
    required this.analysis,
    required this.verification,
    required this.finalDecision,
    required this.analystReview,
    this.reportId,
  });

  IncidentCase copyWith({
    ThreatEvent? event,
    AnalysisResult? analysis,
    VerificationResult? verification,
    FinalDecision? finalDecision,
    AnalystReview? analystReview,
    int? reportId,
  }) {
    return IncidentCase(
      event: event ?? this.event,
      analysis: analysis ?? this.analysis,
      verification: verification ?? this.verification,
      finalDecision: finalDecision ?? this.finalDecision,
      analystReview: analystReview ?? this.analystReview,
      reportId: reportId ?? this.reportId,
    );
  }
}
