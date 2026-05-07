import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:diploma_application_ml/features/event_details/event_details_screen.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:diploma_application_ml/shared/widgets/status_badge.dart';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

class ReportsScreen extends StatelessWidget {
  const ReportsScreen({super.key, required this.controller});

  final AppController controller;

  Future<void> _pickFrom(BuildContext context) async {
    final picked = await showDatePicker(
      context: context,
      initialDate: controller.filterFrom ?? DateTime.now(),
      firstDate: DateTime(2024),
      lastDate: DateTime.now(),
    );
    if (picked == null) return;
    controller.setDateFilter(
      from: DateTime(picked.year, picked.month, picked.day),
      to: controller.filterTo,
    );
    controller.loadReportsFromBackend();
  }

  Future<void> _pickTo(BuildContext context) async {
    final picked = await showDatePicker(
      context: context,
      initialDate: controller.filterTo ?? DateTime.now(),
      firstDate: DateTime(2024),
      lastDate: DateTime.now().add(const Duration(days: 1)),
    );
    if (picked == null) return;
    controller.setDateFilter(
      from: controller.filterFrom,
      // Include the whole selected day.
      to: DateTime(picked.year, picked.month, picked.day, 23, 59, 59),
    );
    controller.loadReportsFromBackend();
  }

  @override
  Widget build(BuildContext context) {
    final fmt = DateFormat('dd MMM yyyy');
    final fromLabel = controller.filterFrom != null
        ? fmt.format(controller.filterFrom!)
        : 'From';
    final toLabel = controller.filterTo != null
        ? fmt.format(controller.filterTo!)
        : 'To';

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        // ── Header row ──────────────────────────────────────────────────────
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('Reports', style: Theme.of(context).textTheme.headlineMedium),
            controller.reportsLoading
                ? const SizedBox(
                    width: 22,
                    height: 22,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : IconButton(
                    icon: const Icon(Icons.refresh),
                    tooltip: 'Refresh from backend',
                    onPressed: controller.loadReportsFromBackend,
                  ),
          ],
        ),
        const SizedBox(height: 12),

        // ── Date filter row ──────────────────────────────────────────────────
        Row(
          children: [
            _DateChip(
              label: fromLabel,
              icon: Icons.calendar_today_outlined,
              active: controller.filterFrom != null,
              onTap: () => _pickFrom(context),
            ),
            const SizedBox(width: 8),
            const Text('—', style: TextStyle(color: Colors.grey)),
            const SizedBox(width: 8),
            _DateChip(
              label: toLabel,
              icon: Icons.calendar_today_outlined,
              active: controller.filterTo != null,
              onTap: () => _pickTo(context),
            ),
            if (controller.hasDateFilter) ...[
              const SizedBox(width: 8),
              InkWell(
                borderRadius: BorderRadius.circular(20),
                onTap: () {
                  controller.clearDateFilter();
                  controller.loadReportsFromBackend();
                },
                child: const Padding(
                  padding: EdgeInsets.all(6),
                  child: Icon(Icons.close, size: 18, color: Colors.redAccent),
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: 20),

        // ── Reports list ─────────────────────────────────────────────────────
        SectionCard(
          title: 'Generated reports',
          subtitle: '${controller.reports.length} shown',
          child: controller.reports.isEmpty
              ? const Padding(
                  padding: EdgeInsets.symmetric(vertical: 24),
                  child: Center(
                    child: Text(
                      'No reports. Press ↻ or adjust the date filter.',
                      style: TextStyle(color: Colors.grey),
                    ),
                  ),
                )
              : Column(
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

class _DateChip extends StatelessWidget {
  const _DateChip({
    required this.label,
    required this.icon,
    required this.active,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final bool active;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final color = active
        ? Theme.of(context).colorScheme.primary
        : Colors.grey.shade600;
    final bg = active
        ? Theme.of(context).colorScheme.primary.withValues(alpha:0.1)
        : Colors.grey.shade100;

    return InkWell(
      borderRadius: BorderRadius.circular(20),
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: color.withValues(alpha:0.4)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: color),
            const SizedBox(width: 6),
            Text(label, style: TextStyle(fontSize: 13, color: color)),
          ],
        ),
      ),
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
                    repository: controller.repository,
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
