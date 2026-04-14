import 'package:diploma_application_ml/domain/models/verification_check.dart';
import 'package:flutter/material.dart';

class VerificationCheckTile extends StatelessWidget {
  const VerificationCheckTile({super.key, required this.check});

  final VerificationCheck check;

  Color _scoreColor(double score) {
    if (score >= 0.7) return const Color(0xFF027A48);
    if (score >= 0.4) return const Color(0xFFB54708);
    return const Color(0xFFC0180C);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final passColor = check.passed
        ? const Color(0xFF027A48)
        : const Color(0xFFB54708);
    final scoreColor = _scoreColor(check.score);
    final scorePct = (check.score * 100).toStringAsFixed(0);
    final weightPct = (check.weight * 100).toStringAsFixed(0);
    final impactPct = (check.score * check.weight * 100).toStringAsFixed(1);

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: passColor.withValues(alpha: 0.20)),
        color: passColor.withValues(alpha: 0.05),
      ),
      child: Theme(
        // Remove ExpansionTile's default divider
        data: theme.copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
          childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
          expandedCrossAxisAlignment: CrossAxisAlignment.start,
          leading: Icon(
            check.passed ? Icons.check_circle : Icons.error_outline,
            color: passColor,
            size: 22,
          ),
          title: Text(
            check.title,
            style: theme.textTheme.titleSmall
                ?.copyWith(fontWeight: FontWeight.w600),
          ),
          subtitle: Text(
            check.passed ? 'Passed' : 'Failed',
            style: TextStyle(
              fontSize: 12,
              color: passColor,
              fontWeight: FontWeight.w500,
            ),
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: scoreColor.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: scoreColor.withValues(alpha: 0.3)),
                ),
                child: Text(
                  '$scorePct%',
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    color: scoreColor,
                  ),
                ),
              ),
              const Icon(Icons.expand_more, size: 18),
            ],
          ),
          children: [
            // ── Score bar ──────────────────────────────────────────────────
            const SizedBox(height: 4),
            Row(
              children: [
                Text(
                  'Score',
                  style: theme.textTheme.bodySmall
                      ?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: check.score.clamp(0.0, 1.0),
                      minHeight: 8,
                      backgroundColor: scoreColor.withValues(alpha: 0.15),
                      valueColor: AlwaysStoppedAnimation(scoreColor),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  '$scorePct / 100',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: scoreColor,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),

            // ── Weight + impact ────────────────────────────────────────────
            Wrap(
              spacing: 8,
              runSpacing: 6,
              children: [
                _InfoChip(
                  icon: Icons.scale_outlined,
                  label: 'Weight',
                  value: '$weightPct%',
                  tooltip:
                      'How much this check contributes to the overall '
                      'verification score.',
                ),
                _InfoChip(
                  icon: Icons.bolt_outlined,
                  label: 'Impact',
                  value: '$impactPct%',
                  tooltip:
                      'Actual contribution to the final decision '
                      '(score × weight).',
                ),
              ],
            ),
            const SizedBox(height: 12),

            // ── Description ────────────────────────────────────────────────
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest
                    .withValues(alpha: 0.5),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        Icons.info_outline,
                        size: 14,
                        color: theme.colorScheme.outline,
                      ),
                      const SizedBox(width: 6),
                      Text(
                        'What this test checks',
                        style: theme.textTheme.labelMedium
                            ?.copyWith(color: theme.colorScheme.outline),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    check.description,
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            ),

            // ── Evidence ───────────────────────────────────────────────────
            if (check.evidence.isNotEmpty) ...[
              const SizedBox(height: 12),
              Row(
                children: [
                  Icon(
                    Icons.list_alt_outlined,
                    size: 14,
                    color: theme.colorScheme.outline,
                  ),
                  const SizedBox(width: 6),
                  Text(
                    'Evidence (${check.evidence.length})',
                    style: theme.textTheme.labelMedium
                        ?.copyWith(color: theme.colorScheme.outline),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              ...check.evidence.map(
                (item) => Padding(
                  padding: const EdgeInsets.only(top: 5),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Padding(
                        padding: const EdgeInsets.only(top: 3),
                        child: Icon(
                          Icons.subdirectory_arrow_right,
                          size: 14,
                          color: passColor.withValues(alpha: 0.7),
                        ),
                      ),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          item,
                          style: theme.textTheme.bodySmall?.copyWith(
                            fontFamily: 'monospace',
                            height: 1.4,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ── Small info chip with tooltip ─────────────────────────────────────────────
class _InfoChip extends StatelessWidget {
  const _InfoChip({
    required this.icon,
    required this.label,
    required this.value,
    required this.tooltip,
  });

  final IconData icon;
  final String label;
  final String value;
  final String tooltip;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Tooltip(
      message: tooltip,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(20),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 13, color: theme.colorScheme.outline),
            const SizedBox(width: 5),
            Text(
              '$label: ',
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: theme.colorScheme.outline),
            ),
            Text(
              value,
              style: theme.textTheme.bodySmall
                  ?.copyWith(fontWeight: FontWeight.w700),
            ),
          ],
        ),
      ),
    );
  }
}
