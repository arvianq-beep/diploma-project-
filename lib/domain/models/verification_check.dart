class VerificationCheck {
  final String key;
  final String title;
  final String description;
  final bool passed;
  final double score;
  final double weight;
  final List<String> evidence;

  const VerificationCheck({
    required this.key,
    required this.title,
    required this.description,
    required this.passed,
    required this.score,
    required this.weight,
    required this.evidence,
  });
}
