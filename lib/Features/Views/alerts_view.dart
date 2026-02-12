import 'package:diploma_application_ml/Features/Home/home_view_model.dart';
import 'package:diploma_application_ml/Features/Views/alert_details_page.dart';
import 'package:flutter/material.dart';

class AlertsView extends StatelessWidget {
  final HomeViewModel vm;
  const AlertsView({super.key, required this.vm});

  @override
  Widget build(BuildContext context) {
    final history = vm.history;

    if (history.isEmpty) {
      return const Center(child: Text('No alerts yet. Run analysis from Dashboard.'));
    }

    return ListView.separated(
      padding: const EdgeInsets.all(12),
      itemCount: history.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (context, i) {
        final r = history[i];
        return Card(
          child: ListTile(
            title: Text(r.decisionStatus),
            subtitle: Text('Label: ${r.prediction.label} | Conf: ${r.prediction.confidence.toStringAsFixed(3)}'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => AlertDetailsPage(result: r)),
            ),
          ),
        );
      },
    );
  }
}
