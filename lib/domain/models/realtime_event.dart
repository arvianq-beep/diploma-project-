/// A single flow result streamed from the real-time monitoring backend.
class RealtimeEvent {
  const RealtimeEvent({
    required this.processedAt,
    required this.srcIp,
    required this.dstIp,
    required this.srcPort,
    required this.dstPort,
    required this.proto,
    required this.detectorLabel,
    required this.detectorConfidence,
    required this.detectorStability,
    required this.finalStatus,
    required this.verificationConfidence,
    required this.recommendedAction,
    required this.triggeredIndicators,
    required this.verificationChecks,
    required this.verificationSummary,
    required this.bytesTransferredKb,
    required this.durationSeconds,
    required this.packetsPerSecond,
    this.reportId,
    this.explanationPending = false,
  });

  final DateTime processedAt;
  final String srcIp;
  final String dstIp;
  final int srcPort;
  final int dstPort;
  final int proto;
  final String detectorLabel;
  final double detectorConfidence;
  final double detectorStability;
  final String finalStatus;
  final double verificationConfidence;
  final String recommendedAction;
  final List<String> triggeredIndicators;
  /// Raw JSON dicts for each of the 5 verification checks from Stage 2.
  final List<Map<String, dynamic>> verificationChecks;
  final String verificationSummary;
  final double bytesTransferredKb;
  final double durationSeconds;
  final double packetsPerSecond;
  final int? reportId;
  final bool explanationPending;

  bool get isThreat => detectorLabel != 'Benign';
  bool get isVerifiedThreat => finalStatus == 'Verified Threat';
  bool get isSuspicious => finalStatus == 'Suspicious';

  factory RealtimeEvent.fromJson(Map<String, dynamic> json) {
    return RealtimeEvent(
      processedAt: DateTime.fromMillisecondsSinceEpoch(
        ((json['processed_at'] as num?)?.toDouble() ?? 0.0) * 1000 ~/ 1,
      ),
      srcIp: (json['src_ip'] ?? '').toString(),
      dstIp: (json['dst_ip'] ?? '').toString(),
      srcPort: (json['src_port'] as num?)?.toInt() ?? 0,
      dstPort: (json['dst_port'] as num?)?.toInt() ?? 0,
      proto: (json['proto'] as num?)?.toInt() ?? 0,
      detectorLabel: (json['detector_label'] ?? 'Unknown').toString(),
      detectorConfidence:
          (json['detector_confidence'] as num?)?.toDouble() ?? 0.0,
      detectorStability:
          (json['detector_stability'] as num?)?.toDouble() ?? 0.0,
      finalStatus: (json['final_status'] ?? 'Unknown').toString(),
      verificationConfidence:
          (json['verification_confidence'] as num?)?.toDouble() ?? 0.0,
      recommendedAction: (json['recommended_action'] ?? '').toString(),
      triggeredIndicators:
          ((json['triggered_indicators'] as List?) ?? const [])
              .map((e) => e.toString())
              .toList(),
      verificationChecks:
          ((json['verification_checks'] as List?) ?? const [])
              .whereType<Map>()
              .map((m) => m.cast<String, dynamic>())
              .toList(),
      verificationSummary:
          (json['verification_summary'] ?? '').toString(),
      bytesTransferredKb:
          (json['bytes_transferred_kb'] as num?)?.toDouble() ?? 0.0,
      durationSeconds:
          (json['duration_seconds'] as num?)?.toDouble() ?? 0.0,
      packetsPerSecond:
          (json['packets_per_second'] as num?)?.toDouble() ?? 0.0,
      reportId: (json['report_id'] as num?)?.toInt(),
      explanationPending: json['explanation_pending'] == true,
    );
  }
}
