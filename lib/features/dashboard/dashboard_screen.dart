import 'package:diploma_application_ml/core/theme/app_theme.dart';
import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/features/event_details/event_details_screen.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/confidence_trend_chart.dart';
import 'package:diploma_application_ml/shared/widgets/distribution_chart.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:diploma_application_ml/shared/widgets/status_badge.dart';
import 'package:diploma_application_ml/shared/widgets/summary_stat_card.dart';
import 'package:flutter/material.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final palette = Theme.of(context).extension<StatusPalette>()!;
    final counts = controller.statusCounts;
    final latest = controller.latestIncident;

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text(
          'AI model for Secure Decision-Making in Cyber Threat Detection Systems',
          style: Theme.of(context).textTheme.headlineMedium,
        ),
        const SizedBox(height: 20),
        GridView.count(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisCount: MediaQuery.of(context).size.width > 900 ? 4 : 2,
          crossAxisSpacing: 14,
          mainAxisSpacing: 14,
          childAspectRatio: 1.25,
          children: [
            SummaryStatCard(
              label: 'Benign',
              value: '${counts[FinalDecisionStatus.benign] ?? 0}',
              color: palette.benign,
              caption: 'Events cleared by AI plus verification checks.',
            ),
            SummaryStatCard(
              label: 'Verified Threat',
              value: '${counts[FinalDecisionStatus.verifiedThreat] ?? 0}',
              color: palette.verifiedThreat,
              caption: 'Threats confirmed by the verification layer.',
            ),
            SummaryStatCard(
              label: 'Suspicious',
              value: '${counts[FinalDecisionStatus.suspicious] ?? 0}',
              color: palette.suspicious,
              caption: 'Cases routed for manual analyst review.',
            ),
            SummaryStatCard(
              label: 'Reports',
              value: '${controller.reports.length}',
              color: Theme.of(context).colorScheme.primary,
              caption: 'Generated analysis artifacts ready for export.',
            ),
          ],
        ),
        const SizedBox(height: 20),
        if (latest != null)
          SectionCard(
            title: 'Current system verdict',
            subtitle:
                'The latest processed event shows how the raw AI output is verified before a final decision is issued.',
            child: _LatestDecisionPreview(incident: latest),
          ),
        const SizedBox(height: 20),
        LayoutBuilder(
          builder: (context, constraints) {
            if (constraints.maxWidth < 900) {
              return Column(
                children: [
                  SectionCard(
                    title: 'Status distribution',
                    subtitle:
                        'Counts of final statuses across processed incidents.',
                    child: DistributionChart(
                      values: [
                        (counts[FinalDecisionStatus.benign] ?? 0).toDouble(),
                        (counts[FinalDecisionStatus.verifiedThreat] ?? 0)
                            .toDouble(),
                        (counts[FinalDecisionStatus.suspicious] ?? 0)
                            .toDouble(),
                      ],
                      colors: [
                        palette.benign,
                        palette.verifiedThreat,
                        palette.suspicious,
                      ],
                      labels: const ['Benign', 'Verified', 'Suspicious'],
                    ),
                  ),
                  const SizedBox(height: 16),
                  SectionCard(
                    title: 'Confidence trend',
                    subtitle: 'Raw AI confidence over the most recent cases.',
                    child: ConfidenceTrendChart(
                      incidents: controller.recentIncidents,
                    ),
                  ),
                ],
              );
            }

            return Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: SectionCard(
                    title: 'Status distribution',
                    subtitle:
                        'Counts of final statuses across processed incidents.',
                    child: DistributionChart(
                      values: [
                        (counts[FinalDecisionStatus.benign] ?? 0).toDouble(),
                        (counts[FinalDecisionStatus.verifiedThreat] ?? 0)
                            .toDouble(),
                        (counts[FinalDecisionStatus.suspicious] ?? 0)
                            .toDouble(),
                      ],
                      colors: [
                        palette.benign,
                        palette.verifiedThreat,
                        palette.suspicious,
                      ],
                      labels: const ['Benign', 'Verified', 'Suspicious'],
                    ),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: SectionCard(
                    title: 'Confidence trend',
                    subtitle: 'Raw AI confidence over the most recent cases.',
                    child: ConfidenceTrendChart(
                      incidents: controller.recentIncidents,
                    ),
                  ),
                ),
              ],
            );
          },
        ),
        const SizedBox(height: 20),
        SectionCard(
          title: 'Recent events',
          subtitle:
              'Use these cases to demonstrate the end-to-end workflow during the defense.',
          child: Column(
            children: controller.recentIncidents
                .map(
                  (incident) => _RecentEventTile(
                    controller: controller,
                    incident: incident,
                  ),
                )
                .toList(),
          ),
        ),
      ],
    );
  }
}

class _LatestDecisionPreview extends StatelessWidget {
  const _LatestDecisionPreview({required this.incident});

  final IncidentCase incident;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 12,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            StatusBadge(incident.finalDecision.status),
            Chip(label: Text('Raw label: ${incident.analysis.rawAiLabel}')),
            Chip(
              label: Text(
                'Confidence: ${formatPercent(incident.analysis.rawConfidence)}',
              ),
            ),
            Chip(
              label: Text(
                'Verification score: ${incident.verification.verificationScore.toStringAsFixed(2)}',
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Text(
          incident.finalDecision.explanation,
          style: Theme.of(context).textTheme.bodyLarge,
        ),
      ],
    );
  }
}

class _RecentEventTile extends StatelessWidget {
  const _RecentEventTile({required this.controller, required this.incident});

  final AppController controller;
  final IncidentCase incident;

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
        title: Text(incident.event.title),
        subtitle: Text(
          '${formatDateTime(incident.event.capturedAt)} • ${incident.analysis.rawAiLabel} • ${incident.event.sourceIp}',
        ),
        trailing: const Icon(Icons.chevron_right),
        leading: StatusBadge(incident.finalDecision.status),
        onTap: () {
          Navigator.of(context).push(
            MaterialPageRoute(
              builder: (_) => EventDetailsScreen(
                controller: controller,
                incident: incident,
                repository: controller.repository,
              ),
            ),
          );
        },
      ),
    );
  }
}
