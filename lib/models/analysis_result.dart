class AnalysisResult {
  final String eventId;
  final String timestampUtc;

  final Prediction prediction;
  final Verification verification;

  final String decisionStatus;
  final String recommendedAction;

  AnalysisResult({
    required this.eventId,
    required this.timestampUtc,
    required this.prediction,
    required this.verification,
    required this.decisionStatus,
    required this.recommendedAction,
  });

  factory AnalysisResult.fromJson(Map<String, dynamic> json) {
    return AnalysisResult(
      eventId: (json['event_id'] ?? '').toString(),
      timestampUtc: (json['timestamp_utc'] ?? '').toString(),
      prediction: Prediction.fromJson(
        (json['prediction'] ?? {}) as Map<String, dynamic>,
      ),
      verification: Verification.fromJson(
        (json['verification'] ?? {}) as Map<String, dynamic>,
      ),
      decisionStatus: (json['decision_status'] ?? '').toString(),
      recommendedAction: (json['recommended_action'] ?? '').toString(),
    );
  }
}

class Prediction {
  final String label;
  final double confidence;

  Prediction({required this.label, required this.confidence});

  factory Prediction.fromJson(Map<String, dynamic> json) {
    final conf = json['confidence'];
    return Prediction(
      label: (json['label'] ?? '').toString(),
      confidence: (conf is num) ? conf.toDouble() : 0.0,
    );
  }
}

class Verification {
  final bool passed;
  final List<VerificationCheck> checks;

  Verification({required this.passed, required this.checks});

  factory Verification.fromJson(Map<String, dynamic> json) {
    final raw = (json['checks'] as List?) ?? const [];
    final parsed = <VerificationCheck>[];

    for (final item in raw) {
      if (item is Map) {
        parsed.add(VerificationCheck.fromJson(item.cast<String, dynamic>()));
      }
    }

    return Verification(passed: json['passed'] == true, checks: parsed);
  }
}

class VerificationCheck {
  final String name;
  final bool passed;
  final String details;

  VerificationCheck({
    required this.name,
    required this.passed,
    required this.details,
  });

  factory VerificationCheck.fromJson(Map<String, dynamic> json) {
    return VerificationCheck(
      name: (json['name'] ?? '').toString(),
      passed: json['passed'] == true,
      details: (json['details'] ?? '').toString(),
    );
  }
}
