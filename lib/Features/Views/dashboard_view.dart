import 'package:diploma_application_ml/Features/Home/home_view_model.dart';
import 'package:flutter/material.dart';


class DashboardView extends StatelessWidget {
  final HomeViewModel vm;
  const DashboardView({super.key, required this.vm});

  Color _statusColor(BuildContext context, String status) {
    if (status.contains('Verified')) return Colors.blue;
    if (status.contains('Suspicious')) return Colors.orange;
    return Colors.green;
  }

  @override
  Widget build(BuildContext context) {
    final r = vm.lastResult;

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                    'Detection → Verification → Decision Status',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: vm.isLoading ? null : vm.runDemoAnalysis,
                    icon: vm.isLoading
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.play_arrow),
                    label: Text(
                      vm.isLoading ? 'Running...' : 'Run demo analysis',
                    ),
                  ),
                  if (vm.error != null) ...[
                    const SizedBox(height: 12),
                    Text(vm.error!, style: const TextStyle(color: Colors.red)),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          if (r != null)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Decision: ${r.decisionStatus}',
                      style: TextStyle(
                        fontWeight: FontWeight.w700,
                        color: _statusColor(context, r.decisionStatus),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text('Label: ${r.prediction.label}'),
                    Text(
                      'Confidence: ${r.prediction.confidence.toStringAsFixed(3)}',
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Verification: ${r.verification.passed ? "PASSED" : "FAILED"}',
                    ),
                    const SizedBox(height: 8),
                    Text('Action: ${r.recommendedAction}'),
                    const SizedBox(height: 12),
                    const Text(
                      'Checks:',
                      style: TextStyle(fontWeight: FontWeight.w700),
                    ),
                    ...r.verification.checks.map(
                      (c) => ListTile(
                        dense: true,
                        leading: Icon(
                          c.passed ? Icons.check_circle : Icons.error,
                          color: c.passed ? Colors.green : Colors.orange,
                        ),
                        title: Text(c.name),
                        subtitle: Text(c.details),
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}
