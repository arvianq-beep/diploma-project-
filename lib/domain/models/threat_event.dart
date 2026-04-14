class ThreatEvent {
  final String id;
  final String title;
  final String description;
  final String sourceIp;
  final String destinationIp;
  final int sourcePort;
  final int destinationPort;
  final String protocol;
  final double bytesTransferredKb;
  final double durationSeconds;
  final double packetsPerSecond;
  final int failedLogins;
  final double anomalyScore;
  final double contextRiskScore;
  final bool knownBadSource;
  final bool offHoursActivity;
  final bool repeatedAttempts;
  final String sampleSource;
  final DateTime capturedAt;
  final List<String> tags;

  /// Canonical 77-feature flow record.
  ///
  /// When non-empty the backend uses the primary 77-feature inference path.
  /// When empty the backend falls back to the 8-field legacy compat mapping.
  /// Keys must match the canonical names defined in rf_ids_features.json.
  final Map<String, double> flowFeatures;

  /// Returns true when this event carries a full (or partial) canonical
  /// 77-feature record that will trigger the primary ML path on the backend.
  bool get hasPrimaryFlowFeatures => flowFeatures.isNotEmpty;

  const ThreatEvent({
    required this.id,
    required this.title,
    required this.description,
    required this.sourceIp,
    required this.destinationIp,
    required this.sourcePort,
    required this.destinationPort,
    required this.protocol,
    required this.bytesTransferredKb,
    required this.durationSeconds,
    required this.packetsPerSecond,
    required this.failedLogins,
    required this.anomalyScore,
    required this.contextRiskScore,
    required this.knownBadSource,
    required this.offHoursActivity,
    required this.repeatedAttempts,
    required this.sampleSource,
    required this.capturedAt,
    required this.tags,
    this.flowFeatures = const {},
  });
}
