import 'dart:convert';

import 'package:diploma_application_ml/domain/models/analysis_result.dart';
import 'package:diploma_application_ml/domain/models/ml_model_info.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';
import 'package:http/http.dart' as http;

class IdsApiService {
  IdsApiService({http.Client? client, this.baseUrl = 'http://127.0.0.1:5001'})
    : _client = client ?? http.Client();

  final http.Client _client;
  final String baseUrl;

  Future<AnalysisResult> analyzeEvent(ThreatEvent event) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/v1/analyze'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'event': _eventToJson(event)}),
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('Backend analyze failed: ${response.statusCode}');
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final prediction =
        (data['prediction'] as Map?)?.cast<String, dynamic>() ?? {};
    final confidence = (prediction['confidence'] as num?)?.toDouble() ?? 0.0;

    return AnalysisResult(
      rawAiLabel: (prediction['label'] ?? 'Unknown').toString(),
      rawConfidence: confidence,
      stabilityScore:
          (prediction['stability_score'] as num?)?.toDouble() ?? 0.0,
      modelVersion: (prediction['model_version'] ?? 'backend-model').toString(),
      reasoning: (prediction['reasoning'] ?? '').toString(),
      alternativeHypothesis: (prediction['alternative_hypothesis'] ?? '')
          .toString(),
      triggeredIndicators:
          ((prediction['triggered_indicators'] as List?) ?? const [])
              .map((item) => item.toString())
              .toList(),
    );
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
    final datasets = ((data['datasets'] as List?) ?? const [])
        .map((item) => item.toString())
        .toList();

    return MlModelInfo(
      backendReachable: true,
      modelAvailable: data['model_available'] == true,
      modelName: (modelInfo['model_name'] ?? 'Random Forest').toString(),
      modelVersion:
          (data['model_version'] ?? modelInfo['model_version'] ?? 'unknown')
              .toString(),
      datasets: datasets,
      metrics: (data['metrics'] as Map?)?.cast<String, dynamic>() ?? {},
      dataMode: data['model_available'] == true
          ? 'trained-model'
          : 'backend-fallback',
    );
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
