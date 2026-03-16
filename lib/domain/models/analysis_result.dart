class AnalysisResult {
  final String rawAiLabel;
  final double rawConfidence;
  final double stabilityScore;
  final String modelVersion;
  final String reasoning;
  final String alternativeHypothesis;
  final List<String> triggeredIndicators;

  const AnalysisResult({
    required this.rawAiLabel,
    required this.rawConfidence,
    required this.stabilityScore,
    required this.modelVersion,
    required this.reasoning,
    required this.alternativeHypothesis,
    required this.triggeredIndicators,
  });
}
