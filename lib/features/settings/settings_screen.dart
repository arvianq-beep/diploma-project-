import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:flutter/material.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final modelInfo = controller.modelInfo;
    final testMetrics =
        (modelInfo.metrics['test'] as Map?)?.cast<String, dynamic>() ?? {};
    final crossDataset =
        (modelInfo.metrics['cross_dataset'] as Map?)?.cast<String, dynamic>() ??
        {};

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text(
          'About the prototype',
          style: Theme.of(context).textTheme.headlineMedium,
        ),
        const SizedBox(height: 8),
        Text(
          'This screen explains the thesis framing, ML module and verification-first architecture for the defense.',
          style: Theme.of(context).textTheme.bodyLarge,
        ),
        const SizedBox(height: 20),
        const SectionCard(
          title: 'Thesis goal',
          child: Text(
            'The application demonstrates an AI-driven intrusion detection workflow where the raw model prediction is never trusted blindly. A verification layer validates confidence, stability, context and rule-based evidence before assigning one of three final statuses: Benign, Verified Threat or Suspicious.',
          ),
        ),
        const SizedBox(height: 16),
        const SectionCard(
          title: 'Architecture overview',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '• domain/: threat event, analysis, verification, final decision, analyst review, reports',
              ),
              Text(
                '• data/: backend-aware repository, CSV import service, verification service, report export service',
              ),
              Text(
                '• backend/ml/: unified preprocessing, Random Forest training, evaluation and inference',
              ),
              Text(
                '• features/: dashboard, analysis, event details, reports, about',
              ),
              Text(
                '• shared/widgets/: reusable cards, badges and charts for the defense flow',
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SectionCard(
          title: 'ML module',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Backend reachable: ${modelInfo.backendReachable}'),
              Text('Trained model available: ${modelInfo.modelAvailable}'),
              Text('Model: ${modelInfo.modelName}'),
              Text('Version: ${modelInfo.modelVersion}'),
              Text('Datasets: ${modelInfo.datasets.join(', ')}'),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SectionCard(
          title: 'Evaluation snapshot',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (testMetrics.isNotEmpty) ...[
                Text('Test accuracy: ${testMetrics['accuracy'] ?? 'n/a'}'),
                Text('Test precision: ${testMetrics['precision'] ?? 'n/a'}'),
                Text('Test recall: ${testMetrics['recall'] ?? 'n/a'}'),
                Text('Test F1-score: ${testMetrics['f1_score'] ?? 'n/a'}'),
                Text(
                  'Test FPR: ${testMetrics['false_positive_rate'] ?? 'n/a'}',
                ),
              ] else
                const Text(
                  'No trained-model metrics are available yet. Train the backend model with CIC-IDS2017 and CIC-UNSW-NB15 artifacts to populate this section.',
                ),
              if (crossDataset.isNotEmpty) ...[
                const SizedBox(height: 10),
                Text(
                  'Cross-dataset accuracy: ${crossDataset['accuracy'] ?? 'n/a'}',
                ),
                Text(
                  'Cross-dataset F1-score: ${crossDataset['f1_score'] ?? 'n/a'}',
                ),
                Text(
                  'Cross-dataset ROC-AUC: ${crossDataset['roc_auc'] ?? 'n/a'}',
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 16),
        const SectionCard(
          title: 'Demo script',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('1. Open Dashboard and explain the three final statuses.'),
              Text('2. Move to Analysis and run a sample event.'),
              Text(
                '3. Show raw AI output first, then the verification checks.',
              ),
              Text('4. Open Event Details and add analyst notes.'),
              Text('5. Open Reports and export a PDF.'),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SectionCard(
          title: 'Current runtime mode',
          child: Text(
            modelInfo.modelAvailable
                ? 'The app is connected to the Python inference service and uses a trained-model path for raw AI prediction before local verification.'
                : 'The backend integration is ready, but a trained artifact was not found at runtime. The app can still fall back to the local heuristic path so the diploma demo remains runnable.',
            style: Theme.of(context).textTheme.bodyLarge,
          ),
        ),
      ],
    );
  }
}
