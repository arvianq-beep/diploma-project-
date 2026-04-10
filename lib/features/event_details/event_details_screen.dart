import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:diploma_application_ml/shared/widgets/status_badge.dart';
import 'package:diploma_application_ml/shared/widgets/verification_check_tile.dart';
import 'package:flutter/material.dart';

class EventDetailsScreen extends StatefulWidget {
  const EventDetailsScreen({
    super.key,
    required this.controller,
    required this.incident,
  });

  final AppController controller;
  final IncidentCase incident;

  @override
  State<EventDetailsScreen> createState() => _EventDetailsScreenState();
}

class _EventDetailsScreenState extends State<EventDetailsScreen> {
  late final TextEditingController analystController;

  @override
  void initState() {
    super.initState();
    analystController = TextEditingController(
      text: widget.incident.analystReview.notes,
    );
  }

  @override
  void dispose() {
    analystController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final incident = widget.controller.history.firstWhere(
      (item) => item.event.id == widget.incident.event.id,
      orElse: () => widget.incident,
    );
    final report = widget.controller.reportForIncident(incident);

    return Scaffold(
      appBar: AppBar(title: const Text('Event details')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          SectionCard(
            title: incident.event.title,
            subtitle: incident.event.description,
            trailing: StatusBadge(incident.finalDecision.status),
            child: Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                _MetaChip(label: 'Source', value: incident.event.sourceIp),
                _MetaChip(
                  label: 'Destination',
                  value: incident.event.destinationIp,
                ),
                _MetaChip(label: 'Protocol', value: incident.event.protocol),
                _MetaChip(
                  label: 'Captured',
                  value: formatDateTime(incident.event.capturedAt),
                ),
                _MetaChip(
                  label: 'Bytes',
                  value:
                      '${incident.event.bytesTransferredKb.toStringAsFixed(0)} KB',
                ),
                _MetaChip(
                  label: 'Pkt/s',
                  value: incident.event.packetsPerSecond.toStringAsFixed(0),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          SectionCard(
            title: 'Raw AI prediction',
            subtitle: 'Primary model output before verification.',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  children: [
                    Chip(label: Text('Label: ${incident.analysis.rawAiLabel}')),
                    Chip(
                      label: Text(
                        'Confidence: ${formatPercent(incident.analysis.rawConfidence)}',
                      ),
                    ),
                    Chip(
                      label: Text(
                        'Stability: ${incident.analysis.stabilityScore.toStringAsFixed(2)}',
                      ),
                    ),
                    Chip(
                      label: Text('Model: ${incident.analysis.modelVersion}'),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Text(incident.analysis.reasoning),
                const SizedBox(height: 12),
                Text(
                  'Alternative hypothesis: ${incident.analysis.alternativeHypothesis}',
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          SectionCard(
            title: 'Verification layer',
            subtitle:
                'The backend verifier combines neural confidence with stability, context and cross-evidence checks.',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Model before verification: ${incident.analysis.rawAiLabel} '
                  '(${formatPercent(incident.analysis.rawConfidence)})',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                const SizedBox(height: 16),
                Text(
                  'Verification score: ${incident.verification.verificationScore.toStringAsFixed(2)}',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                const SizedBox(height: 16),
                Text(incident.verification.summary),
                const SizedBox(height: 14),
                ...incident.verification.checks.map(
                  (check) => VerificationCheckTile(check: check),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          SectionCard(
            title: 'Final decision and analyst view',
            subtitle:
                '',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(incident.finalDecision.explanation),
                const SizedBox(height: 12),
                Text(
                  'Recommended analyst action: ${incident.finalDecision.recommendedAnalystAction}',
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: analystController,
                  minLines: 3,
                  maxLines: 5,
                  decoration: const InputDecoration(
                    labelText: 'Analyst notes',
                    hintText:
                        'Add analyst interpretation, false-positive note or escalation comment.',
                  ),
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  children: [
                    FilledButton.icon(
                      onPressed: () {
                        widget.controller.saveAnalystNotes(
                          incident: incident,
                          analystName: 'SOC Analyst',
                          notes: analystController.text,
                        );
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Analyst notes saved')),
                        );
                      },
                      icon: const Icon(Icons.save_outlined),
                      label: const Text('Save notes'),
                    ),
                    OutlinedButton.icon(
                      onPressed: report == null
                          ? null
                          : () async {
                              await widget.controller.exportReport(report);
                            },
                      icon: const Icon(Icons.picture_as_pdf_outlined),
                      label: const Text('Export report PDF'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _MetaChip extends StatelessWidget {
  const _MetaChip({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Text('$label: $value'),
    );
  }
}
