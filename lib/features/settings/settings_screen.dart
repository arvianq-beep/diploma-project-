import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

const kAnalystNameKey = 'analyst_name';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.controller});

  final AppController controller;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final TextEditingController _nameController = TextEditingController();

  int? _feedbackCount;
  bool _feedbackLoading = false;
  bool _retraining = false;
  String? _retrainResult;
  bool _retrainError = false;

  @override
  void initState() {
    super.initState();
    _loadAnalystName();
    _loadFeedbackCount();
  }

  @override
  void dispose() {
    _nameController.dispose();
    super.dispose();
  }

  Future<void> _loadAnalystName() async {
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString(kAnalystNameKey) ?? '';
    if (mounted) setState(() => _nameController.text = stored);
  }

  Future<void> _saveAnalystName(String name) async {
    final prefs = await SharedPreferences.getInstance();
    if (name.trim().isEmpty) {
      await prefs.remove(kAnalystNameKey);
    } else {
      await prefs.setString(kAnalystNameKey, name.trim());
    }
  }

  Future<void> _loadFeedbackCount() async {
    setState(() => _feedbackLoading = true);
    try {
      final count = await widget.controller.repository.fetchFeedbackCount();
      if (mounted) setState(() => _feedbackCount = count);
    } catch (_) {
      if (mounted) setState(() => _feedbackCount = 0);
    } finally {
      if (mounted) setState(() => _feedbackLoading = false);
    }
  }

  Future<void> _triggerRetrain() async {
    setState(() {
      _retraining = true;
      _retrainResult = null;
      _retrainError = false;
    });
    try {
      final result = await widget.controller.repository.triggerFineTune();
      if (!mounted) return;
      final status = result['status'] as String? ?? '';
      if (status == 'ok') {
        final samples = result['feedback_samples'] as int? ?? 0;
        final replay = result['replay_samples'] as int? ?? 0;
        final driftStatus =
            (result['drift'] as Map?)?['status'] as String? ?? 'n/a';
        setState(() {
          _retrainResult =
              'Done — trained on $samples feedback + $replay replay samples. '
              'Drift: $driftStatus.';
          _retrainError = false;
        });
      } else {
        final reason = result['reason'] as String? ?? 'skipped';
        final found = result['found'] as int?;
        final required = result['required'] as int?;
        setState(() {
          _retrainResult = reason == 'too_few_feedback_samples' && found != null
              ? 'Skipped — only $found verdicts found, $required required.'
              : 'Skipped: $reason.';
          _retrainError = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _retrainResult = 'Error: $e';
          _retrainError = true;
        });
      }
    } finally {
      if (mounted) setState(() => _retraining = false);
      _loadFeedbackCount();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final modelInfo = widget.controller.modelInfo;
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
          style: theme.textTheme.headlineMedium,
        ),
        const SizedBox(height: 8),
        Text(
          'This screen explains the thesis framing, ML module and verification-first architecture for the defense.',
          style: theme.textTheme.bodyLarge,
        ),
        const SizedBox(height: 20),

        // ── Analyst identity ───────────────────────────────────────────────
        SectionCard(
          title: 'Analyst identity',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Your name is shown on saved analyst notes and exported reports.',
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _nameController,
                decoration: const InputDecoration(
                  labelText: 'Display name',
                  hintText: 'SOC Analyst',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                textInputAction: TextInputAction.done,
                onSubmitted: _saveAnalystName,
                onEditingComplete: () =>
                    _saveAnalystName(_nameController.text),
              ),
              const SizedBox(height: 8),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton.icon(
                  onPressed: () {
                    _saveAnalystName(_nameController.text);
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Analyst name saved.')),
                    );
                  },
                  icon: const Icon(Icons.save_outlined, size: 16),
                  label: const Text('Save'),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),

        // ── Model feedback & retraining ────────────────────────────────────
        SectionCard(
          title: 'Model feedback & retraining',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Analyst verdicts submitted from Event Details are stored in the '
                'backend database and used to fine-tune the verifier ensemble.',
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 14),
              Row(
                children: [
                  const Icon(Icons.rate_review_outlined, size: 18),
                  const SizedBox(width: 8),
                  _feedbackLoading
                      ? const SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Text(
                          'Stored verdicts: ${_feedbackCount ?? 0}',
                          style: theme.textTheme.bodyMedium
                              ?.copyWith(fontWeight: FontWeight.w600),
                        ),
                  const Spacer(),
                  IconButton(
                    onPressed: _feedbackLoading ? null : _loadFeedbackCount,
                    icon: const Icon(Icons.refresh, size: 18),
                    tooltip: 'Refresh count',
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: _retraining ? null : _triggerRetrain,
                icon: _retraining
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Icon(Icons.model_training, size: 18),
                label: Text(_retraining ? 'Retraining…' : 'Trigger retraining'),
              ),
              if (_retrainResult != null) ...[
                const SizedBox(height: 10),
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: (_retrainError
                            ? Colors.red
                            : theme.colorScheme.primary)
                        .withValues(alpha: 0.08),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: (_retrainError
                              ? Colors.red
                              : theme.colorScheme.primary)
                          .withValues(alpha: 0.3),
                    ),
                  ),
                  child: Text(
                    _retrainResult!,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: _retrainError
                          ? Colors.red
                          : theme.colorScheme.primary,
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 16),

        // ── Thesis goal ────────────────────────────────────────────────────
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
            style: theme.textTheme.bodyLarge,
          ),
        ),
      ],
    );
  }
}
