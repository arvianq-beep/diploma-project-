import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/batch_analysis_summary.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';
import 'package:diploma_application_ml/features/event_details/event_details_screen.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/pipeline_stage_card.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:diploma_application_ml/shared/widgets/status_badge.dart';
import 'package:diploma_application_ml/shared/widgets/verification_check_tile.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

class AnalysisScreen extends StatelessWidget {
  const AnalysisScreen({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final incident = controller.latestIncident;
    final selected = controller.selectedEvent;
    final batchSummary = controller.lastBatchSummary;

    return Stack(
      children: [
        ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Text(
              'Analysis Pipeline',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Run a sample through the backend detector, then review the server-side verification result and final decision.',
              style: Theme.of(context).textTheme.bodyLarge,
            ),
            const SizedBox(height: 20),
            SectionCard(
              title: 'ML inference status',
              subtitle:
                  'The Flutter app requests the full detector + verifier decision from the Python backend.',
              child: Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  Chip(label: Text('Mode: ${controller.modelInfo.dataMode}')),
                  Chip(label: Text('Model: ${controller.modelInfo.modelName}')),
                  Chip(
                    label: Text(
                      'Version: ${controller.modelInfo.modelVersion}',
                    ),
                  ),
                  Chip(
                    label: Text(
                      controller.modelInfo.backendReachable
                          ? 'Backend reachable'
                          : 'Backend offline',
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),
            LayoutBuilder(
              builder: (context, constraints) {
                final pipeline = _PipelineOverview(controller: controller);
                final selector = _EventSelector(
                  controller: controller,
                  selected: selected,
                );
                if (constraints.maxWidth < 960) {
                  return Column(
                    children: [selector, const SizedBox(height: 16), pipeline],
                  );
                }
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(flex: 4, child: selector),
                    const SizedBox(width: 16),
                    Expanded(flex: 5, child: pipeline),
                  ],
                );
              },
            ),
            const SizedBox(height: 20),
            if (batchSummary != null) _BatchSummaryCard(summary: batchSummary),
            if (batchSummary != null) const SizedBox(height: 20),
            if (incident != null)
              SectionCard(
                title: 'Latest analysis result',
                subtitle:
                    'This view explicitly separates raw prediction from verified decision.',
                trailing: StatusBadge(incident.finalDecision.status),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Wrap(
                      spacing: 12,
                      runSpacing: 12,
                      children: [
                        Chip(
                          label: Text(
                            'Raw AI label: ${incident.analysis.rawAiLabel}',
                          ),
                        ),
                        Chip(
                          label: Text(
                            'Raw confidence: ${formatPercent(incident.analysis.rawConfidence)}',
                          ),
                        ),
                        Chip(
                          label: Text(
                            'Stability: ${incident.analysis.stabilityScore.toStringAsFixed(2)}',
                          ),
                        ),
                        Chip(
                          label: Text(
                            'Verification: ${incident.verification.verificationScore.toStringAsFixed(2)}',
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    Text(
                      incident.finalDecision.explanation,
                      style: Theme.of(context).textTheme.bodyLarge,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Triggered indicators',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    ...incident.analysis.triggeredIndicators.map(
                      (item) => Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Text(
                          '• $item',
                          style: Theme.of(context).textTheme.bodyMedium,
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'Verification checks',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 10),
                    ...incident.verification.checks.map(
                      (check) => VerificationCheckTile(check: check),
                    ),
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 12,
                      runSpacing: 12,
                      children: [
                        FilledButton.icon(
                          onPressed: () {
                            controller.submitLatestForReview();
                            final reviewIncident =
                                controller.latestIncident ?? incident;
                            Navigator.of(context).push(
                              MaterialPageRoute(
                                builder: (_) => EventDetailsScreen(
                                  controller: controller,
                                  incident: reviewIncident,
                                ),
                              ),
                            );
                          },
                          icon: const Icon(Icons.fact_check_outlined),
                          label: const Text('Send to analyst review'),
                        ),
                        OutlinedButton.icon(
                          onPressed: () {
                            Navigator.of(context).push(
                              MaterialPageRoute(
                                builder: (_) => EventDetailsScreen(
                                  controller: controller,
                                  incident: incident,
                                ),
                              ),
                            );
                          },
                          icon: const Icon(Icons.open_in_new),
                          label: const Text('Open event details'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
          ],
        ),
        if (controller.isAnalyzing)
          Positioned.fill(
            child: Container(
              color: Colors.white.withValues(alpha: 0.72),
              alignment: Alignment.center,
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 360),
                child: Card(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const SizedBox(
                          width: 42,
                          height: 42,
                          child: CircularProgressIndicator(strokeWidth: 3),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          controller.isImporting
                              ? 'Processing dataset'
                              : 'Processing event',
                          style: Theme.of(context).textTheme.titleMedium,
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          controller.loadingMessage,
                          style: Theme.of(context).textTheme.bodyMedium,
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 16),
                        SizedBox(
                          width: double.infinity,
                          child: controller.loadingProgress != null
                              ? Column(
                                  children: [
                                    LinearProgressIndicator(
                                      value: controller.loadingProgress,
                                      minHeight: 8,
                                      borderRadius: BorderRadius.circular(999),
                                    ),
                                    const SizedBox(height: 8),
                                    Text(
                                      '${(controller.loadingProgress! * 100).toStringAsFixed(0)}%',
                                      style: Theme.of(
                                        context,
                                      ).textTheme.bodySmall,
                                    ),
                                  ],
                                )
                              : const LinearProgressIndicator(
                                  minHeight: 8,
                                  borderRadius: BorderRadius.all(
                                    Radius.circular(999),
                                  ),
                                ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}

class _EventSelector extends StatelessWidget {
  const _EventSelector({required this.controller, required this.selected});

  final AppController controller;
  final ThreatEvent? selected;

  @override
  Widget build(BuildContext context) {
    final selectedValue =
        controller.sampleEvents.any((event) => event.id == selected?.id)
        ? selected?.id
        : null;

    return SectionCard(
      title: 'Sample input event',
      subtitle:
          'Choose a sample event or import a CSV file. Imported rows are converted into ThreatEvent objects and analyzed through the ML backend.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DropdownButtonFormField<String>(
            initialValue: selectedValue,
            items: controller.sampleEvents
                .map(
                  (event) => DropdownMenuItem<String>(
                    value: event.id,
                    child: Text(event.title),
                  ),
                )
                .toList(),
            onChanged: (value) {
              final event = controller.sampleEvents.firstWhere(
                (item) => item.id == value,
              );
              controller.selectSample(event);
            },
            decoration: const InputDecoration(labelText: 'Demo sample'),
          ),
          if (selectedValue == null && selected != null) ...[
            const SizedBox(height: 12),
            Text(
              'Imported CSV event selected: ${selected!.title}',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ],
          const SizedBox(height: 16),
          if (selected != null) _EventSummary(event: selected!),
          const SizedBox(height: 18),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              FilledButton.icon(
                onPressed: controller.isAnalyzing
                    ? null
                    : controller.runAnalysis,
                icon: controller.isAnalyzing && !controller.isImporting
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.play_arrow),
                label: Text(
                  controller.isAnalyzing && !controller.isImporting
                      ? 'Analyzing...'
                      : 'Run analysis',
                ),
              ),
              OutlinedButton.icon(
                onPressed: controller.isAnalyzing
                    ? null
                    : () async {
                        final result = await FilePicker.platform.pickFiles(
                          type: FileType.custom,
                          allowedExtensions: const ['csv'],
                        );
                        final path = result?.files.single.path;
                        if (path != null) {
                          await controller.importFromFile(path);
                        }
                      },
                icon: controller.isAnalyzing && controller.isImporting
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.upload_file_outlined),
                label: Text(
                  controller.isAnalyzing && controller.isImporting
                      ? 'Importing CSV...'
                      : 'Import CSV',
                ),
              ),
            ],
          ),
          if (controller.error != null) ...[
            const SizedBox(height: 12),
            Text(
              controller.error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
        ],
      ),
    );
  }
}

class _EventSummary extends StatelessWidget {
  const _EventSummary({required this.event});

  final ThreatEvent event;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(18),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(event.title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(
            event.description,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              Chip(label: Text('${event.sourceIp} -> ${event.destinationIp}')),
              Chip(label: Text('${event.protocol} / ${event.destinationPort}')),
              Chip(
                label: Text('Anomaly ${event.anomalyScore.toStringAsFixed(2)}'),
              ),
              Chip(
                label: Text(
                  'Context ${event.contextRiskScore.toStringAsFixed(2)}',
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _PipelineOverview extends StatelessWidget {
  const _PipelineOverview({required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final phase = controller.analysisPhase;
    return SectionCard(
      title: 'Verification-first pipeline',
      subtitle:
          'The final status is only assigned after the verification layer validates the raw AI output.',
      child: LayoutBuilder(
        builder: (context, constraints) {
          final maxWidth = constraints.maxWidth;
          final columns = maxWidth > 1200 ? 4 : 2;
          final spacing = 12.0;
          final cardWidth = columns == 1
              ? maxWidth
              : (maxWidth - (spacing * (columns - 1))) / columns;

          final cards = [
            PipelineStageCard(
              title: '1. Input event',
              description:
                  'Load a sample network event or parse a CSV dataset into ThreatEvent records.',
              active: phase == AnalysisPhase.idle,
              completed: phase != AnalysisPhase.idle,
            ),
            PipelineStageCard(
              title: '2. Raw AI prediction',
              description:
                  'Primary model outputs a raw label and confidence score.',
              active: phase == AnalysisPhase.rawAiRunning,
              completed:
                  phase == AnalysisPhase.verificationRunning ||
                  phase == AnalysisPhase.ready,
            ),
            PipelineStageCard(
              title: '3. Verification layer',
              description:
                  'A backend MLP verifies detector confidence, perturbation stability, context consistency and cross-evidence.',
              active: phase == AnalysisPhase.verificationRunning,
              completed: phase == AnalysisPhase.ready,
            ),
            PipelineStageCard(
              title: '4. Final decision',
              description:
                  'System issues Benign, Verified Threat or Suspicious with analyst action.',
              active: phase == AnalysisPhase.ready,
              completed: phase == AnalysisPhase.ready,
            ),
          ];

          return Wrap(
            spacing: spacing,
            runSpacing: spacing,
            children: cards
                .map((card) => SizedBox(width: cardWidth, child: card))
                .toList(),
          );
        },
      ),
    );
  }
}

class _BatchSummaryCard extends StatelessWidget {
  const _BatchSummaryCard({required this.summary});

  final BatchAnalysisSummary summary;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      title: 'CSV batch analysis summary',
      subtitle:
          'Imported rows were parsed into ThreatEvent objects and evaluated through ML + verification.',
      child: Wrap(
        spacing: 12,
        runSpacing: 12,
        children: [
          Chip(label: Text('Source: ${summary.sourceName.split('/').last}')),
          Chip(label: Text('Processed: ${summary.processed}')),
          Chip(label: Text('Benign: ${summary.benign}')),
          Chip(label: Text('Verified Threat: ${summary.verifiedThreat}')),
          Chip(label: Text('Suspicious: ${summary.suspicious}')),
          Chip(
            label: Text('Generated: ${formatDateTime(summary.generatedAt)}'),
          ),
        ],
      ),
    );
  }
}
