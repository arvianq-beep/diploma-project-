class ReportSummary {
  final int total;
  final int normal;
  final int nonNormal;
  final int verifiedThreat;
  final int suspicious;

  const ReportSummary({
    required this.total,
    required this.normal,
    required this.nonNormal,
    required this.verifiedThreat,
    required this.suspicious,
  });

  factory ReportSummary.fromJson(Map<String, dynamic> json) {
    int asInt(dynamic v) => (v is num) ? v.toInt() : 0;

    return ReportSummary(
      total: asInt(json['total']),
      normal: asInt(json['normal']),
      nonNormal: asInt(json['non_normal']),
      verifiedThreat: asInt(json['verified_threat']),
      suspicious: asInt(json['suspicious']),
    );
  }
}

class ReportItem {
  final int id;
  final String createdAt;
  final String label;
  final double confidence;
  final String decisionStatus;
  final String? decisionReason;
  final Map<String, dynamic>? trafficContext;
  final Map<String, dynamic>? rawInput;

  const ReportItem({
    required this.id,
    required this.createdAt,
    required this.label,
    required this.confidence,
    required this.decisionStatus,
    this.decisionReason,
    this.trafficContext,
    this.rawInput,
  });

  factory ReportItem.fromJson(Map<String, dynamic> json) {
    double asDouble(dynamic v) => (v is num) ? v.toDouble() : 0.0;

    Map<String, dynamic>? asMap(dynamic v) {
      if (v is Map<String, dynamic>) return v;
      return null;
    }

    return ReportItem(
      id: (json['id'] as num).toInt(),
      createdAt: (json['created_at'] ?? '').toString(),
      label: (json['label'] ?? '').toString(),
      confidence: asDouble(json['confidence']),
      decisionStatus: (json['decision_status'] ?? '').toString(),
      decisionReason: json['decision_reason']?.toString(),
      trafficContext: asMap(json['traffic_context']),
      rawInput: asMap(json['raw_input']),
    );
  }
}

class ReportsResponse {
  final ReportSummary summary;
  final List<ReportItem> items;
  final int limit;
  final int offset;

  const ReportsResponse({
    required this.summary,
    required this.items,
    required this.limit,
    required this.offset,
  });

  factory ReportsResponse.fromJson(Map<String, dynamic> json) {
    final summary = ReportSummary.fromJson(
      (json['summary'] as Map).cast<String, dynamic>(),
    );
    final itemsJson = (json['items'] as List).cast<dynamic>();
    final items = itemsJson
        .whereType<Map>()
        .map((e) => ReportItem.fromJson(e.cast<String, dynamic>()))
        .toList();

    return ReportsResponse(
      summary: summary,
      items: items,
      limit: (json['limit'] as num).toInt(),
      offset: (json['offset'] as num).toInt(),
    );
  }
}
