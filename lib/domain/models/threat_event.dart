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
  });
}
