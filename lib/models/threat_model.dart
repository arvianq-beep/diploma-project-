class ThreatLog {
  final String id;
  final String timestamp; // Строка, чтобы избежать ошибок с DateTime
  final String sourceIp;
  final String protocol;
  final String threatType;
  final bool isThreat;
  final double aiConfidence; // Внимание: именно aiConfidence
  final bool isVerified;
  final String verificationDetails;

  ThreatLog({
    required this.id,
    required this.timestamp,
    required this.sourceIp,
    required this.protocol,
    required this.threatType,
    required this.isThreat,
    required this.aiConfidence,
    required this.isVerified,
    required this.verificationDetails,
  });

  factory ThreatLog.fromJson(Map<String, dynamic> json) {
    return ThreatLog(
      id:
          json['id']?.toString() ??
          DateTime.now().millisecondsSinceEpoch.toString(),
      timestamp: json['timestamp']?.toString() ?? "",
      sourceIp: json['source_ip']?.toString() ?? "Unknown",
      protocol: json['protocol']?.toString() ?? "TCP",
      threatType: json['threat_type']?.toString() ?? "Normal",
      isThreat: json['is_threat'] ?? false,
      aiConfidence: (json['ai_confidence'] ?? 0.0).toDouble(),
      isVerified: json['is_verified'] ?? false,
      verificationDetails: json['verification_details']?.toString() ?? "",
    );
  }
}
