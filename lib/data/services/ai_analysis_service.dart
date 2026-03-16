import 'dart:math';

import 'package:diploma_application_ml/domain/models/analysis_result.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';

class AiAnalysisService {
  const AiAnalysisService();

  AnalysisResult analyze(ThreatEvent event) {
    final threatScore = _threatScore(event);
    final rawAiLabel = threatScore >= 0.52 ? _pickThreatLabel(event) : 'Benign';
    final rawConfidence = rawAiLabel == 'Benign'
        ? _clamp01(0.58 + ((0.52 - threatScore) * 0.9))
        : _clamp01(0.53 + ((threatScore - 0.52) * 1.05));
    final stabilityScore = _stabilityScore(event, rawConfidence);
    final indicators = _indicators(event);

    return AnalysisResult(
      rawAiLabel: rawAiLabel,
      rawConfidence: rawConfidence,
      stabilityScore: stabilityScore,
      modelVersion: 'Mock Ensemble v2.3',
      reasoning: _reasoningFor(event, rawAiLabel, indicators),
      alternativeHypothesis: _alternativeHypothesis(event, rawAiLabel),
      triggeredIndicators: indicators,
    );
  }

  double _threatScore(ThreatEvent event) {
    var score = (event.anomalyScore * 0.28) + (event.contextRiskScore * 0.18);

    if (event.knownBadSource) score += 0.16;
    if (event.offHoursActivity) score += 0.09;
    if (event.repeatedAttempts) score += 0.10;
    if (event.failedLogins >= 6) score += 0.18;
    if (event.bytesTransferredKb >= 10000) score += 0.15;
    if (event.packetsPerSecond >= 600) score += 0.14;
    if (event.protocol == 'ICMP') score += 0.04;
    if (event.protocol == 'UDP' && event.destinationPort == 53) score -= 0.08;
    if (event.tags.contains('expected-service')) score -= 0.12;

    return _clamp01(score);
  }

  double _stabilityScore(ThreatEvent event, double confidence) {
    var score = 0.42 + (confidence * 0.24);

    if (event.knownBadSource) score += 0.10;
    if (event.repeatedAttempts) score += 0.08;
    if (event.failedLogins >= 6) score += 0.10;
    if (event.tags.contains('diagnostics-window')) score -= 0.13;
    if (event.bytesTransferredKb >= 10000 && !event.knownBadSource) {
      score -= 0.04;
    }

    return _clamp01(score);
  }

  String _pickThreatLabel(ThreatEvent event) {
    if (event.failedLogins >= 6) {
      return 'Credential Abuse';
    }
    if (event.bytesTransferredKb >= 10000) {
      return 'Data Exfiltration';
    }
    if (event.packetsPerSecond >= 600 || event.protocol == 'ICMP') {
      return 'Reconnaissance';
    }
    return 'Malicious Activity';
  }

  List<String> _indicators(ThreatEvent event) {
    final indicators = <String>[];

    if (event.knownBadSource) {
      indicators.add('Source IP matches a known-bad intelligence feed.');
    }
    if (event.failedLogins >= 6) {
      indicators.add(
        'Repeated authentication failures suggest brute-force behavior.',
      );
    }
    if (event.bytesTransferredKb >= 10000) {
      indicators.add(
        'Outbound transfer volume exceeds the baseline for this asset.',
      );
    }
    if (event.packetsPerSecond >= 600) {
      indicators.add(
        'Packet rate exceeds the expected profile for normal traffic.',
      );
    }
    if (event.offHoursActivity) {
      indicators.add(
        'Activity occurred outside the host’s normal operating window.',
      );
    }
    if (event.repeatedAttempts) {
      indicators.add(
        'Repeated connection attempts indicate scanning or retry behavior.',
      );
    }
    if (indicators.isEmpty) {
      indicators.add(
        'Network features stay within the expected operational baseline.',
      );
    }

    return indicators;
  }

  String _alternativeHypothesis(ThreatEvent event, String label) {
    if (label == 'Benign') {
      return 'Low-volume scheduled service traffic remains the strongest competing explanation.';
    }
    if (event.tags.contains('diagnostics-window')) {
      return 'Scheduled diagnostics could explain part of the observed ICMP burst.';
    }
    if (event.bytesTransferredKb >= 10000) {
      return 'Large backup synchronization is an alternate explanation, but timing increases risk.';
    }
    return 'Benign burst traffic is the main alternative hypothesis.';
  }

  String _reasoningFor(
    ThreatEvent event,
    String label,
    List<String> indicators,
  ) {
    if (label == 'Benign') {
      return 'The model treats this event as benign because traffic volume, context risk and behavioral indicators stay close to the learned baseline.';
    }

    final dominantIndicator = indicators.first;
    return 'The primary model flags $label because $dominantIndicator';
  }

  double _clamp01(double value) => max(0, min(1, value));
}
