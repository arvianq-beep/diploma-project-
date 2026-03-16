import 'package:diploma_application_ml/core/theme/app_theme.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:flutter/material.dart';

class StatusBadge extends StatelessWidget {
  const StatusBadge(this.status, {super.key});

  final FinalDecisionStatus status;

  @override
  Widget build(BuildContext context) {
    final palette = Theme.of(context).extension<StatusPalette>()!;
    final color = switch (status) {
      FinalDecisionStatus.benign => palette.benign,
      FinalDecisionStatus.verifiedThreat => palette.verifiedThreat,
      FinalDecisionStatus.suspicious => palette.suspicious,
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        status.label,
        style: TextStyle(color: color, fontWeight: FontWeight.w700),
      ),
    );
  }
}
