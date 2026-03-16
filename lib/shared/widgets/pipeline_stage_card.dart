import 'package:flutter/material.dart';

class PipelineStageCard extends StatelessWidget {
  const PipelineStageCard({
    super.key,
    required this.title,
    required this.description,
    required this.active,
    required this.completed,
  });

  final String title;
  final String description;
  final bool active;
  final bool completed;

  @override
  Widget build(BuildContext context) {
    final color = completed
        ? Theme.of(context).colorScheme.primary
        : active
        ? Theme.of(context).colorScheme.tertiary
        : Colors.blueGrey.shade200;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            completed
                ? Icons.check_circle
                : active
                ? Icons.timelapse
                : Icons.radio_button_unchecked,
            color: color,
          ),
          const SizedBox(height: 14),
          Text(title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(description, style: Theme.of(context).textTheme.bodyMedium),
        ],
      ),
    );
  }
}
