import 'dart:convert';

import 'package:diploma_application_ml/domain/models/analysis_result.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/final_decision.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/domain/models/ml_model_info.dart';
import 'package:diploma_application_ml/domain/models/realtime_event.dart';
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
    final checks = _buildVerificationChecks(verificationDetails);

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
      reportId: (data['report_id'] as num?)?.toInt(),
      aiExplanation: _nullIfEmpty(data['ai_explanation']),
      aiRecommendations: _nullIfEmpty(data['ai_recommendations']),
      explanationPending: data['explanation_pending'] == true,
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

  String? _nullIfEmpty(Object? value) {
    if (value == null) return null;
    final s = value.toString().trim();
    return s.isEmpty ? null : s;
  }

  /// Fetch the asynchronously-generated AI fields for a report.
  ///
  /// `aiExplanation` is populated for every analyzed report.
  /// `aiRecommendations` is populated only for reports with status `Suspicious`.
  /// Both fields may be `null` for a few seconds after analysis while Ollama is generating.
  Future<({String? aiExplanation, String? aiRecommendations})>
      fetchReportAiAnalysis(int reportId) async {
    final response = await _client.get(
      Uri.parse('$baseUrl/api/v1/reports/$reportId'),
    );
    if (response.statusCode == 404) {
      return (aiExplanation: null, aiRecommendations: null);
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('Fetch report failed: ${response.statusCode}');
    }
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    return (
      aiExplanation: _nullIfEmpty(data['ai_explanation']),
      aiRecommendations: _nullIfEmpty(data['ai_recommendations']),
    );
  }

  /// Submit analyst verdict for a stored report.
  ///
  /// [verdict] must be one of: confirmed_threat, confirmed_benign,
  ///   false_positive, false_negative.
  Future<void> submitAnalystFeedback({
    required int reportId,
    required String verdict,
    String? notes,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/v1/reports/$reportId/feedback'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'verdict': verdict,
        if (notes != null && notes.isNotEmpty) 'notes': notes,
      }),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('Feedback failed: ${response.statusCode}');
    }
  }

  List<VerificationCheck> _buildVerificationChecks(
    Map<String, dynamic> vd,
  ) {
    final md = (vd['model_decision'] as Map?)?.cast<String, dynamic>() ?? {};
    final unc = (vd['uncertainty'] as Map?)?.cast<String, dynamic>() ?? {};
    final ss = (vd['support_scores'] as Map?)?.cast<String, dynamic>() ?? {};
    final pa = (vd['perturbation_analysis'] as Map?)?.cast<String, dynamic>() ?? {};
    final fi = (vd['feature_importance'] as Map?)?.cast<String, dynamic>() ?? {};
    final top5 = ((fi['top_5'] as List?) ?? const [])
        .whereType<Map>()
        .map((e) => e.cast<String, dynamic>())
        .toList();

    final probability = (md['probability'] as num?)?.toDouble() ?? 0.0;
    final aboveThreshold = md['above_threshold'] == true;
    final threshold = (md['threshold_used'] as num?)?.toDouble() ?? 0.5;
    final thresholdType = (md['threshold_type'] ?? 'general').toString();

    final stdDev = (unc['std_deviation'] as num?)?.toDouble() ?? 0.0;
    final isUncertain = unc['is_uncertain'] == true;
    final meanProb = (unc['mean_probability'] as num?)?.toDouble() ?? probability;
    final mcSamples = (unc['mc_samples'] as num?)?.toInt() ?? 30;
    final ensembleMembers = (unc['ensemble_members'] as num?)?.toInt() ?? 0;

    final contextScore = (ss['context_consistency_score'] as num?)?.toDouble() ?? 0.0;
    final evidenceScore = (ss['cross_evidence_score'] as num?)?.toDouble() ?? 0.0;
    final alignmentScore = (ss['support_alignment_score'] as num?)?.toDouble() ?? 0.0;

    final labelConsistency = (pa['label_consistency_ratio'] as num?)?.toDouble() ?? 0.0;
    final confidenceDrop = (pa['confidence_drop'] as num?)?.toDouble() ?? 0.0;
    final stdConf = (pa['std_confidence'] as num?)?.toDouble() ?? 0.0;
    final pertPassed = labelConsistency >= 0.74 && confidenceDrop <= 0.18;

    final uncertaintyScore = (1.0 - stdDev * 5.0).clamp(0.0, 1.0);

    return [
      VerificationCheck(
        key: 'neural_ensemble',
        title: 'Neural Ensemble Decision',
        description:
            'An ensemble of $ensembleMembers MLP models voted on the trustworthiness '
            'of the Stage-1 detector output. Score is the Platt-calibrated ensemble probability.',
        passed: aboveThreshold,
        score: probability,
        weight: 0.35,
        evidence: [
          'Probability: ${probability.toStringAsFixed(4)}',
          'Threshold ($thresholdType): ${threshold.toStringAsFixed(4)}',
          aboveThreshold
              ? 'Decision: above threshold → verified'
              : 'Decision: below threshold → not verified',
        ],
      ),
      VerificationCheck(
        key: 'mc_uncertainty',
        title: 'MC Dropout Uncertainty',
        description:
            'Monte Carlo dropout runs $mcSamples forward passes with active dropout '
            'to estimate epistemic uncertainty. High std (> 0.12) routes to analyst review.',
        passed: !isUncertain,
        score: uncertaintyScore,
        weight: 0.20,
        evidence: [
          'Mean probability: ${meanProb.toStringAsFixed(4)}',
          'Std deviation: ${stdDev.toStringAsFixed(4)}',
          'Uncertain: ${isUncertain ? "yes — routed to analyst" : "no"}',
          'MC passes: $mcSamples × $ensembleMembers models',
        ],
      ),
      VerificationCheck(
        key: 'context_support',
        title: 'Context & Evidence Support',
        description:
            'Context consistency and cross-evidence scores measure how well event '
            'behavioral signals (port, failed logins, timing, repeated attempts) '
            'align with the detector verdict.',
        passed: alignmentScore >= 0.50,
        score: alignmentScore,
        weight: 0.20,
        evidence: [
          'Context consistency: ${contextScore.toStringAsFixed(4)}',
          'Cross-evidence score: ${evidenceScore.toStringAsFixed(4)}',
          'Support alignment: ${alignmentScore.toStringAsFixed(4)}',
        ],
      ),
      VerificationCheck(
        key: 'perturbation_stability',
        title: 'Perturbation Stability',
        description:
            'The detector was re-run on 6 slightly modified flow variants '
            '(rate ±6%, duration ±8%, byte/packet balance shifts). '
            'High label consistency and low confidence drop confirm robustness.',
        passed: pertPassed,
        score: labelConsistency,
        weight: 0.15,
        evidence: [
          'Label consistency: ${(labelConsistency * 100).toStringAsFixed(0)}%',
          'Confidence drop: ${confidenceDrop.toStringAsFixed(4)}',
          'Confidence std across variants: ${stdConf.toStringAsFixed(4)}',
          pertPassed
              ? 'Stability: passed (consistency ≥ 74%, drop ≤ 0.18)'
              : 'Stability: failed',
        ],
      ),
      VerificationCheck(
        key: 'feature_attribution',
        title: 'Integrated Gradients Attribution',
        description:
            'Integrated Gradients computes per-feature attributions against a '
            'background baseline, revealing which signals drove the verifier\'s decision.',
        passed: top5.isNotEmpty,
        score: top5.isNotEmpty ? 1.0 : 0.0,
        weight: 0.10,
        evidence: top5.map((f) {
          final feature = (f['feature'] ?? '').toString();
          final attr = (f['attribution'] as num?)?.toDouble() ?? 0.0;
          return '$feature: ${attr >= 0 ? "+" : ""}${attr.toStringAsFixed(4)}';
        }).toList(),
      ),
    ];
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

  // ---------------------------------------------------------------------------
  // Real-time monitoring
  // ---------------------------------------------------------------------------

  /// Start the backend real-time monitor.
  ///
  /// [source] — "synthetic" | "csv" | "pyshark" | "scapy"
  /// [csvPath] — required when source == "csv"
  /// [batchSize] — flows per inference batch (default 32)
  Future<void> startRealtime({
    String source = 'synthetic',
    int batchSize = 32,
    double rateLimit = 0.05,
    String? interface,
  }) async {
    final body = <String, dynamic>{
      'source': source,
      'batch_size': batchSize,
      'rate_limit': rateLimit,
      if (interface != null && interface.isNotEmpty) 'interface': interface,
    };
    final response = await _client.post(
      Uri.parse('$baseUrl/api/realtime/start'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode == 409) return; // already running — treat as ok
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final msg =
          (jsonDecode(response.body) as Map<String, dynamic>?)?['error'] ??
          'start failed';
      throw Exception('Realtime start failed: $msg');
    }
  }

  /// Stop the backend real-time monitor.
  Future<void> stopRealtime() async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/realtime/stop'),
    );
    if (response.statusCode == 409) return; // already stopped — treat as ok
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final msg =
          (jsonDecode(response.body) as Map<String, dynamic>?)?['error'] ??
          'stop failed';
      throw Exception('Realtime stop failed: $msg');
    }
  }

  /// Poll for new results since the last call.
  ///
  /// Returns a record of (events, isRunning).
  Future<({List<RealtimeEvent> events, bool running})> pollRealtimeResults()
      async {
    final response = await _client.get(
      Uri.parse('$baseUrl/api/realtime/results'),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('Realtime poll failed: ${response.statusCode}');
    }
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final running = data['running'] == true;
    final events = ((data['results'] as List?) ?? const [])
        .whereType<Map<String, dynamic>>()
        .map(RealtimeEvent.fromJson)
        .toList();
    return (events: events, running: running);
  }

  /// Returns available network interfaces for pyshark/scapy, filtered to
  /// physical adapters only. Each entry: {value, label}.
  /// Throws Exception with backend error details if available.
  Future<List<({String value, String label})>> fetchRealtimeInterfaces(
    String source,
  ) async {
    try {
      final response = await _client.get(
        Uri.parse('$baseUrl/api/realtime/interfaces'),
      );
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw Exception('Failed to fetch interfaces: ${response.statusCode}');
      }
      final data = jsonDecode(response.body) as Map<String, dynamic>;

      // Check for backend errors
      final errors = (data['errors'] as Map<String, dynamic>?) ?? {};
      if (errors.containsKey(source)) {
        throw Exception('${source.toUpperCase()} error: ${errors[source]}');
      }

      if (source == 'pyshark') {
        final list = (data['pyshark'] as List?) ?? const [];
        return list
            .whereType<Map<String, dynamic>>()
            .where((m) {
              final name = m['name'] as String? ?? '';
              final desc = m['description'] as String? ?? '';
              // Skip loopback and virtual adapters on all platforms
              return name.isNotEmpty &&
                  !name.toLowerCase().contains('loopback') &&
                  !name.toLowerCase().startsWith('lo') &&
                  !desc.toLowerCase().contains('loopback') &&
                  !desc.toLowerCase().contains('wan miniport');
            })
            .map((m) {
              final name = m['name'] as String? ?? '';
              final desc = m['description'] as String? ?? '';
              // Windows: extract bare GUID from \Device\NPF_{GUID}
              // Mac/Linux: use interface name directly (en0, eth0, etc.)
              final value = name.contains(r'\Device\NPF_{')
                  ? name.replaceAll(r'\Device\NPF_{', '').replaceAll('}', '')
                  : name;
              return (value: value, label: desc.isNotEmpty ? desc : name);
            })
            .toList();
      }

      if (source == 'scapy') {
        final list = (data['scapy'] as List?) ?? const [];
        return list
            .whereType<Map<String, dynamic>>()
            .where((m) {
              final ips = (m['ips'] as List?) ?? const [];
              final ipv4 = ips.where(
                (ip) => !ip.toString().contains(':'),
              );
              final desc = (m['description'] as String? ?? '').toLowerCase();
              return ipv4.isNotEmpty &&
                  !desc.contains('loopback') &&
                  !desc.contains('wan miniport') &&
                  !desc.contains('teredo') &&
                  !desc.contains('6to4');
            })
            .map((m) {
              final name = m['name'] as String? ?? '';
              final desc = m['description'] as String? ?? '';
              final ipv4 = ((m['ips'] as List?) ?? const [])
                  .where((ip) => !ip.toString().contains(':'))
                  .join(', ');
              return (
                value: name,
                label: ipv4.isNotEmpty ? '$desc  ($ipv4)' : desc,
              );
            })
            .toList();
      }

      return [];
    } catch (e) {
      throw Exception('Failed to fetch $source interfaces: $e');
    }
  }

  /// Fetch monitor status without draining results.
  Future<Map<String, dynamic>> fetchRealtimeStatus() async {
    final response = await _client.get(
      Uri.parse('$baseUrl/api/realtime/status'),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return {'running': false};
    }
    return (jsonDecode(response.body) as Map<String, dynamic>?) ?? {};
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
