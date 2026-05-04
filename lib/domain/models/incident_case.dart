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
  /// LLM-generated natural-language explanation. Populated asynchronously by Ollama.
  final String? aiExplanation;
  /// LLM-generated investigation recommendations. Populated only for Suspicious incidents.
  final String? aiRecommendations;

  const IncidentCase({
    required this.event,
    required this.analysis,
    required this.verification,
    required this.finalDecision,
    required this.analystReview,
    this.reportId,
    this.aiExplanation,
    this.aiRecommendations,
  });

  IncidentCase copyWith({
    ThreatEvent? event,
    AnalysisResult? analysis,
    VerificationResult? verification,
    FinalDecision? finalDecision,
    AnalystReview? analystReview,
    int? reportId,
    String? aiExplanation,
    String? aiRecommendations,
  }) {
    return IncidentCase(
      event: event ?? this.event,
      analysis: analysis ?? this.analysis,
      verification: verification ?? this.verification,
      finalDecision: finalDecision ?? this.finalDecision,
      analystReview: analystReview ?? this.analystReview,
      reportId: reportId ?? this.reportId,
      aiExplanation: aiExplanation ?? this.aiExplanation,
      aiRecommendations: aiRecommendations ?? this.aiRecommendations,
    );
  }
}
