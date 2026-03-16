class MlModelInfo {
  final bool backendReachable;
  final bool modelAvailable;
  final String modelName;
  final String modelVersion;
  final List<String> datasets;
  final Map<String, dynamic> metrics;
  final String dataMode;

  const MlModelInfo({
    required this.backendReachable,
    required this.modelAvailable,
    required this.modelName,
    required this.modelVersion,
    required this.datasets,
    required this.metrics,
    required this.dataMode,
  });

  factory MlModelInfo.fallback() {
    return const MlModelInfo(
      backendReachable: false,
      modelAvailable: false,
      modelName: 'Local fallback heuristic',
      modelVersion: 'fallback',
      datasets: ['CIC-IDS2017', 'CIC-UNSW-NB15 (Augmented)'],
      metrics: {},
      dataMode: 'fallback',
    );
  }
}
