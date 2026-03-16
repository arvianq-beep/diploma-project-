import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/verification_check.dart';
import 'package:flutter/material.dart';

class VerificationCheckTile extends StatelessWidget {
  const VerificationCheckTile({super.key, required this.check});

  final VerificationCheck check;

  @override
  Widget build(BuildContext context) {
    final color = check.passed
        ? const Color(0xFF027A48)
        : const Color(0xFFB54708);

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: color.withValues(alpha: 0.16)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                check.passed ? Icons.check_circle : Icons.error_outline,
                color: color,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  check.title,
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ),
              Text(
                formatPercent(check.score),
                style: TextStyle(color: color, fontWeight: FontWeight.w700),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            check.description,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 10),
          ...check.evidence.map(
            (item) => Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                '• $item',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
