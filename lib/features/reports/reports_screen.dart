import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:diploma_application_ml/features/event_details/event_details_screen.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:diploma_application_ml/shared/widgets/status_badge.dart';
import 'package:flutter/material.dart';

class ReportsScreen extends StatelessWidget {
  const ReportsScreen({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text('Reports', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 8),
        Text(
          'Every processed event produces a structured report with event metadata, raw AI output, verification results and analyst notes.',
          style: Theme.of(context).textTheme.bodyLarge,
        ),
        const SizedBox(height: 20),
        SectionCard(
          title: 'Generated reports',
          subtitle:
              'Open a case, review the summary or export a PDF for your diploma presentation.',
          child: Column(
            children: controller.reports
                .map(
                  (report) =>
                      _ReportTile(controller: controller, report: report),
                )
                .toList(),
          ),
        ),
      ],
    );
  }
}

class _ReportTile extends StatelessWidget {
  const _ReportTile({required this.controller, required this.report});

  final AppController controller;
  final ReportModel report;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(18),
      ),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 8),
        leading: StatusBadge(report.status),
        title: Text(report.incident.event.title),
        subtitle: Text(
          '${formatDateTime(report.generatedAt)}\n${report.summary}',
        ),
        isThreeLine: true,
        trailing: PopupMenuButton<String>(
          onSelected: (value) async {
            if (value == 'details') {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => EventDetailsScreen(
                    controller: controller,
                    incident: report.incident,
                  ),
                ),
              );
            }
            if (value == 'pdf') {
              await controller.exportReport(report);
            }
          },
          itemBuilder: (context) => const [
            PopupMenuItem(value: 'details', child: Text('Open details')),
            PopupMenuItem(value: 'pdf', child: Text('Export PDF')),
          ],
        ),
      ),
    );
  }
}
