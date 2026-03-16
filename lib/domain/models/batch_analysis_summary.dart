class BatchAnalysisSummary {
  final String sourceName;
  final int processed;
  final int benign;
  final int verifiedThreat;
  final int suspicious;
  final DateTime generatedAt;

  const BatchAnalysisSummary({
    required this.sourceName,
    required this.processed,
    required this.benign,
    required this.verifiedThreat,
    required this.suspicious,
    required this.generatedAt,
  });
}
