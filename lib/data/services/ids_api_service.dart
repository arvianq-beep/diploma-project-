import 'dart:convert';

import 'package:diploma_application_ml/domain/models/analysis_result.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/final_decision.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/domain/models/ml_model_info.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';
import 'package:diploma_application_ml/domain/models/verification_check.dart';
import 'package:diploma_application_ml/domain/models/verification_result.dart';
import 'package:http/http.dart' as http;

class IdsApiService {
  IdsApiService({http.Client? client, this.baseUrl = 'http://127.0.0.1:5001'})
    : _client = client ?? http.Client();

  final http.Client _client;
  final String baseUrl;

  Future<IncidentCase> analyzeEvent(ThreatEvent event) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/v1/analyze'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'event': _eventToJson(event)}),
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('Backend analyze failed: ${response.statusCode}');
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    return _incidentFromResponse(event, data);
  }

  Future<MlModelInfo> fetchModelInfo() async {
    final response = await _client.get(
      Uri.parse('$baseUrl/api/v1/ml/metadata'),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('Backend metadata failed: ${response.statusCode}');
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final modelInfo =
        (data['model_info'] as Map?)?.cast<String, dynamic>() ?? {};
    final verifier =
        (data['verifier'] as Map?)?.cast<String, dynamic>() ?? {};
    final verifierModelInfo =
        (verifier['model_info'] as Map?)?.cast<String, dynamic>() ?? {};
    final datasets = ((data['datasets'] as List?) ?? const [])
        .map((item) => item.toString())
        .toList();

    return MlModelInfo(
      backendReachable: true,
      modelAvailable: data['model_available'] == true,
      modelName:
          '${(modelInfo['model_name'] ?? 'Random Forest').toString()} + ${(verifierModelInfo['model_name'] ?? 'Verifier MLP').toString()}',
      modelVersion:
          '${(data['model_version'] ?? modelInfo['model_version'] ?? 'unknown').toString()} / ${(verifier['model_version'] ?? verifierModelInfo['model_version'] ?? 'unknown').toString()}',
      datasets: datasets,
      metrics: {
        'detector': (data['metrics'] as Map?)?.cast<String, dynamic>() ?? {},
        'verifier': (verifier['metrics'] as Map?)?.cast<String, dynamic>() ?? {},
      },
      dataMode:
          data['model_available'] == true && verifier['model_available'] == true
          ? 'backend-detector+verifier'
          : 'backend-partial-fallback',
    );
  }

  IncidentCase _incidentFromResponse(
    ThreatEvent event,
    Map<String, dynamic> data,
  ) {
    final prediction =
        (data['prediction'] as Map?)?.cast<String, dynamic>() ?? {};
    final detectorDetails =
        (data['detector_details'] as Map?)?.cast<String, dynamic>() ?? {};
    final verificationDetails =
        (data['verification_details'] as Map?)?.cast<String, dynamic>() ?? {};
    final checks =
        ((verificationDetails['checks'] as List?) ?? const [])
            .whereType<Map>()
            .map((check) => _verificationCheckFromJson(check))
            .toList();

    final analysis = AnalysisResult(
      rawAiLabel:
          (data['detector_label'] ?? prediction['label'] ?? 'Unknown')
              .toString(),
      rawConfidence:
          (data['ai_confidence'] as num?)?.toDouble() ??
          (prediction['confidence'] as num?)?.toDouble() ??
          0.0,
      stabilityScore:
          (detectorDetails['stability_score'] as num?)?.toDouble() ??
          (prediction['stability_score'] as num?)?.toDouble() ??
          0.0,
      modelVersion:
          (data['detector_model_version'] ?? prediction['model_version'] ?? 'backend-model')
              .toString(),
      reasoning:
          (detectorDetails['reasoning'] ?? prediction['reasoning'] ?? '')
              .toString(),
      alternativeHypothesis:
          (detectorDetails['alternative_hypothesis'] ??
                  prediction['alternative_hypothesis'] ??
                  '')
              .toString(),
      triggeredIndicators:
          ((detectorDetails['triggered_indicators'] as List?) ??
                  (prediction['triggered_indicators'] as List?) ??
                  const [])
              .map((item) => item.toString())
              .toList(),
    );

    final verification = VerificationResult(
      checks: checks,
      passed: data['is_verified'] == true,
      verificationScore:
          (data['verification_confidence'] as num?)?.toDouble() ?? 0.0,
      explanationNotes: [
        'Verification executed on the Python backend as Stage 2.',
        'Verifier model version: ${(data['verifier_model_version'] ?? 'unknown').toString()}',
        'Threshold used: ${verificationDetails['threshold_used'] ?? 'n/a'}',
      ],
      summary: (verificationDetails['summary'] ?? '').toString(),
    );

    final status = _statusFromLabel(
      (data['final_decision_status'] ?? 'Suspicious').toString(),
    );
    final finalDecision = FinalDecision(
      rawAiLabel: analysis.rawAiLabel,
      rawConfidence: analysis.rawConfidence,
      verificationChecks: checks,
      status: status,
      explanation: verification.summary,
      timestamp:
          DateTime.tryParse((data['timestamp_utc'] ?? '').toString()) ??
          DateTime.now(),
      recommendedAnalystAction:
          (data['recommended_action'] ?? status.analystAction).toString(),
    );

    return IncidentCase(
      event: event,
      analysis: analysis,
      verification: verification,
      finalDecision: finalDecision,
      analystReview: AnalystReview(
        state: status == FinalDecisionStatus.suspicious
            ? AnalystReviewState.pending
            : AnalystReviewState.reviewed,
        analystName: 'SOC Analyst',
        notes: status == FinalDecisionStatus.suspicious
            ? 'Awaiting analyst validation of backend verification disagreement.'
            : 'Backend detector and verifier pipeline completed automatically.',
        updatedAt: DateTime.now(),
      ),
    );
  }

  VerificationCheck _verificationCheckFromJson(Map<dynamic, dynamic> rawCheck) {
    final check = rawCheck.cast<String, dynamic>();
    return VerificationCheck(
      key: (check['key'] ?? '').toString(),
      title: (check['title'] ?? '').toString(),
      description: (check['description'] ?? '').toString(),
      passed: check['passed'] == true,
      score: (check['score'] as num?)?.toDouble() ?? 0.0,
      weight: (check['weight'] as num?)?.toDouble() ?? 0.0,
      evidence:
          ((check['evidence'] as List?) ?? const [])
              .map((item) => item.toString())
              .toList(),
    );
  }

  FinalDecisionStatus _statusFromLabel(String label) {
    switch (label) {
      case 'Benign':
        return FinalDecisionStatus.benign;
      case 'Verified Threat':
        return FinalDecisionStatus.verifiedThreat;
      case 'Suspicious':
      default:
        return FinalDecisionStatus.suspicious;
    }
  }

  Map<String, dynamic> _eventToJson(ThreatEvent event) {
    return {
      'id': event.id,
      'title': event.title,
      'description': event.description,
      'source_ip': event.sourceIp,
      'destination_ip': event.destinationIp,
      'source_port': event.sourcePort,
      'destination_port': event.destinationPort,
      'protocol': event.protocol,
      'bytes_transferred_kb': event.bytesTransferredKb,
      'duration_seconds': event.durationSeconds,
      'packets_per_second': event.packetsPerSecond,
      'failed_logins': event.failedLogins,
      'anomaly_score': event.anomalyScore,
      'context_risk_score': event.contextRiskScore,
      'known_bad_source': event.knownBadSource,
      'off_hours_activity': event.offHoursActivity,
      'repeated_attempts': event.repeatedAttempts,
      'sample_source': event.sampleSource,
      'captured_at': event.capturedAt.toIso8601String(),
      'tags': event.tags,
    };
  }
}
