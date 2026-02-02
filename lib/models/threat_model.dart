class ThreatLog {
  final String timestamp;
  final String sourceIp;
  final String protocol;
  final String threatType;
  final bool isThreat;
  final double aiConfidence;
  final bool isVerified;
  final String verificationDetails;

  ThreatLog({
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
      timestamp: json['timestamp'] ?? "",
      sourceIp: json['source_ip'] ?? "Unknown",
      protocol: json['protocol'] ?? "TCP",
      threatType: json['threat_type'] ?? "Normal",
      isThreat: json['is_threat'] ?? false,
      aiConfidence: (json['ai_confidence'] ?? 0.0).toDouble(),
      isVerified: json['is_verified'] ?? false,
      verificationDetails: json['verification_details'] ?? "",
    );
  }
}