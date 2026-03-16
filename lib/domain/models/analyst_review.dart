enum AnalystReviewState { pending, reviewed }

class AnalystReview {
  final AnalystReviewState state;
  final String analystName;
  final String notes;
  final DateTime updatedAt;

  const AnalystReview({
    required this.state,
    required this.analystName,
    required this.notes,
    required this.updatedAt,
  });

  AnalystReview copyWith({
    AnalystReviewState? state,
    String? analystName,
    String? notes,
    DateTime? updatedAt,
  }) {
    return AnalystReview(
      state: state ?? this.state,
      analystName: analystName ?? this.analystName,
      notes: notes ?? this.notes,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }
}
