import 'package:flutter/material.dart';
import '../../../Models/analysis_result.dart';

class AlertDetailsPage extends StatelessWidget {
  final AnalysisResult result;
  const AlertDetailsPage({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    final r = result;

    return Scaffold(
      appBar: AppBar(title: const Text('Alert Details')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Event ID: ${r.eventId}'),
          Text('Timestamp (UTC): ${r.timestampUtc}'),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Decision: ${r.decisionStatus}',
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 8),
                  Text('Prediction: ${r.prediction.label}'),
                  Text(
                    'Confidence: ${r.prediction.confidence.toStringAsFixed(3)}',
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Verification: ${r.verification.passed ? "PASSED" : "FAILED"}',
                  ),
                  const SizedBox(height: 8),
                  Text('Action: ${r.recommendedAction}'),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          const Text(
            'Verification checks',
            style: TextStyle(fontWeight: FontWeight.w700),
          ),
          ...r.verification.checks.map(
            (c) => Card(
              child: ListTile(
                leading: Icon(
                  c.passed ? Icons.check_circle : Icons.error,
                  color: c.passed ? Colors.green : Colors.orange,
                ),
                title: Text(c.name),
                subtitle: Text(c.details),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
