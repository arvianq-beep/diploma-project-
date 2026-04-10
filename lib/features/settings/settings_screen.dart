import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:flutter/material.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final modelInfo = controller.modelInfo;
    final detectorMetrics =
        (modelInfo.metrics['detector'] as Map?)?.cast<String, dynamic>() ?? {};
    final verifierMetrics =
        (modelInfo.metrics['verifier'] as Map?)?.cast<String, dynamic>() ?? {};
    final testMetrics =
        (detectorMetrics['test'] as Map?)?.cast<String, dynamic>() ?? {};
    final crossDataset =
        (detectorMetrics['cross_dataset'] as Map?)?.cast<String, dynamic>() ??
        {};
    final verifierTestMetrics =
        (verifierMetrics['test'] as Map?)?.cast<String, dynamic>() ?? {};

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
            'The application demonstrates an AI-driven intrusion detection workflow where the raw detector prediction is never trusted blindly. A backend verification layer validates confidence, stability, context and cross-evidence before assigning one of three final statuses: Benign, Verified Threat or Suspicious.',
          ),
        ),
        const SizedBox(height: 16),
        const SectionCard(
          title: 'Architecture overview',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'domain/: threat event, analysis, verification, final decision, analyst review, reports',
              ),
              Text(
                'data/: backend-aware repository, CSV import service, backend-response adapter, report export service',
              ),
              Text(
                'backend/ml/: Stage 1 detector preprocessing, Random Forest training, evaluation and inference',
              ),
              Text(
                'backend/verification/: Stage 2 verifier features, PyTorch MLP, inference and artifacts',
              ),
              Text(
                'features/: dashboard, analysis, event details, reports, about',
              ),
              Text(
                'shared/widgets/: reusable cards, badges and charts for the defense flow',
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
              Text('Detector model available: ${modelInfo.modelAvailable}'),
              Text('Pipeline: ${modelInfo.modelName}'),
              Text('Versions: ${modelInfo.modelVersion}'),
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
                Text('Detector test accuracy: ${testMetrics['accuracy'] ?? 'n/a'}'),
                Text('Detector test precision: ${testMetrics['precision'] ?? 'n/a'}'),
                Text('Detector test recall: ${testMetrics['recall'] ?? 'n/a'}'),
                Text('Detector test F1-score: ${testMetrics['f1_score'] ?? 'n/a'}'),
                Text(
                  'Detector test FPR: ${testMetrics['false_positive_rate'] ?? 'n/a'}',
                ),
              ] else
                const Text(
                  'No detector metrics are available yet. Train the backend detector model with CIC-IDS2017 and CIC-UNSW-NB15 artifacts to populate this section.',
                ),
              if (crossDataset.isNotEmpty) ...[
                const SizedBox(height: 10),
                Text(
                  'Detector cross-dataset accuracy: ${crossDataset['accuracy'] ?? 'n/a'}',
                ),
                Text(
                  'Detector cross-dataset F1-score: ${crossDataset['f1_score'] ?? 'n/a'}',
                ),
                Text(
                  'Detector cross-dataset ROC-AUC: ${crossDataset['roc_auc'] ?? 'n/a'}',
                ),
              ],
              if (verifierTestMetrics.isNotEmpty) ...[
                const SizedBox(height: 10),
                Text(
                  'Verifier test accuracy: ${verifierTestMetrics['accuracy'] ?? 'n/a'}',
                ),
                Text(
                  'Verifier test F1-score: ${verifierTestMetrics['f1_score'] ?? 'n/a'}',
                ),
                Text(
                  'Verifier test ROC-AUC: ${verifierTestMetrics['roc_auc'] ?? 'n/a'}',
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
                '3. Show raw detector output first, then the backend verification checks.',
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
                ? 'The app is connected to the Python pipeline and receives backend-side detector plus verifier decisions.'
                : 'The backend integration is ready, but a trained detector artifact was not found at runtime. The app can still fall back to the local heuristic demo path so the diploma presentation remains runnable.',
            style: Theme.of(context).textTheme.bodyLarge,
          ),
        ),
      ],
    );
  }
}
