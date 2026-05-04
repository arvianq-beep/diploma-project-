import 'dart:async';

import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/data/repositories/ids_repository.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/shared/widgets/section_card.dart';
import 'package:diploma_application_ml/shared/widgets/status_badge.dart';
import 'package:diploma_application_ml/shared/widgets/verification_check_tile.dart';
import 'package:flutter/material.dart';

// Allowed verdicts with their display labels, icons, and colors.
const _verdicts = [
  _VerdictOption(
    value: 'confirmed_threat',
    label: 'Confirmed Threat',
    description: 'This is a real attack — detector was correct.',
    icon: Icons.gpp_bad_outlined,
    color: Color(0xFFDC2626),
  ),
  _VerdictOption(
    value: 'confirmed_benign',
    label: 'Confirmed Benign',
    description: 'This is normal traffic — detector was correct.',
    icon: Icons.verified_outlined,
    color: Color(0xFF16A34A),
  ),
  _VerdictOption(
    value: 'false_positive',
    label: 'False Positive',
    description: 'Flagged as threat but it\'s actually benign.',
    icon: Icons.remove_circle_outline,
    color: Color(0xFFD97706),
  ),
  _VerdictOption(
    value: 'false_negative',
    label: 'False Negative',
    description: 'Missed a real attack — marked as benign.',
    icon: Icons.warning_amber_outlined,
    color: Color(0xFF7C3AED),
  ),
];

class EventDetailsScreen extends StatefulWidget {
  const EventDetailsScreen({
    super.key,
    required this.controller,
    required this.incident,
    required this.repository,
  });

  final AppController controller;
  final IncidentCase incident;
  final IdsRepository repository;

  @override
  State<EventDetailsScreen> createState() => _EventDetailsScreenState();
}

class _EventDetailsScreenState extends State<EventDetailsScreen> {
  late final TextEditingController _notesController;
  String? _selectedVerdict;
  bool _feedbackSubmitting = false;
  bool _feedbackSubmitted = false;

  // Async LLM artifacts. Populated by polling /api/v1/reports/<id>.
  String? _aiExplanation;
  String? _aiRecommendations;
  bool _aiLoading = false;
  Timer? _aiPollTimer;
  int _aiPollAttempts = 0;

  static const _aiPollInterval = Duration(seconds: 2);
  static const _aiPollMaxAttempts = 30; // ~60 s ceiling

  @override
  void initState() {
    super.initState();
    _notesController = TextEditingController(
      text: widget.incident.analystReview.notes,
    );
    _aiExplanation = widget.incident.aiExplanation;
    _aiRecommendations = widget.incident.aiRecommendations;
    _maybeStartAiPolling();
  }

  @override
  void dispose() {
    _aiPollTimer?.cancel();
    _notesController.dispose();
    super.dispose();
  }

  bool get _aiComplete {
    if (_aiExplanation == null || _aiExplanation!.isEmpty) return false;
    final isSuspicious =
        widget.incident.finalDecision.status == FinalDecisionStatus.suspicious;
    if (!isSuspicious) return true;
    return _aiRecommendations != null && _aiRecommendations!.isNotEmpty;
  }

  void _maybeStartAiPolling() {
    final reportId = widget.incident.reportId;
    if (reportId == null || _aiComplete) return;
    _aiLoading = true;
    _aiPollTimer = Timer.periodic(_aiPollInterval, (_) => _pollAiAnalysis());
    // Trigger an immediate first attempt so we don't wait the full interval.
    _pollAiAnalysis();
  }

  Future<void> _pollAiAnalysis() async {
    final reportId = widget.incident.reportId;
    if (reportId == null) {
      _aiPollTimer?.cancel();
      return;
    }
    _aiPollAttempts += 1;
    final result = await widget.repository.fetchReportAiAnalysis(reportId);
    if (!mounted) return;
    setState(() {
      if (result.aiExplanation != null) {
        _aiExplanation = result.aiExplanation;
      }
      if (result.aiRecommendations != null) {
        _aiRecommendations = result.aiRecommendations;
      }
      if (_aiComplete || _aiPollAttempts >= _aiPollMaxAttempts) {
        _aiLoading = false;
        _aiPollTimer?.cancel();
      }
    });
  }

  Future<void> _submitFeedback() async {
    final reportId = widget.incident.reportId;
    if (reportId == null) {
      _showSnack('No report ID — this incident was not saved to the database.');
      return;
    }
    if (_selectedVerdict == null) {
      _showSnack('Select a verdict before submitting.');
      return;
    }
    setState(() => _feedbackSubmitting = true);
    try {
      await widget.repository.submitAnalystFeedback(
        reportId: reportId,
        verdict: _selectedVerdict!,
        notes: _notesController.text.trim().isEmpty
            ? null
            : _notesController.text.trim(),
      );
      setState(() => _feedbackSubmitted = true);
      _showSnack('Analyst verdict saved — will be used for model fine-tuning.');
    } catch (e) {
      _showSnack('Failed to submit verdict: $e');
    } finally {
      setState(() => _feedbackSubmitting = false);
    }
  }

  void _showSnack(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
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
          // ── Event metadata ─────────────────────────────────────────────────
          SectionCard(
            title: incident.event.title,
            subtitle: incident.event.description,
            trailing: StatusBadge(incident.finalDecision.status),
            child: Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                _MetaChip(label: 'Source', value: incident.event.sourceIp),
                _MetaChip(label: 'Destination', value: incident.event.destinationIp),
                _MetaChip(label: 'Protocol', value: incident.event.protocol),
                _MetaChip(label: 'Captured', value: formatDateTime(incident.event.capturedAt)),
                _MetaChip(
                  label: 'Bytes',
                  value: '${incident.event.bytesTransferredKb.toStringAsFixed(0)} KB',
                ),
                _MetaChip(
                  label: 'Pkt/s',
                  value: incident.event.packetsPerSecond.toStringAsFixed(0),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // ── Raw AI prediction ──────────────────────────────────────────────
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
                    Chip(label: Text('Model: ${incident.analysis.modelVersion}')),
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

          // ── Verification layer ─────────────────────────────────────────────
          SectionCard(
            title: 'Verification layer',
            subtitle:
                'The backend ensemble verifier combines neural confidence, '
                'MC uncertainty, and integrated gradients attribution.',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Model before verification: ${incident.analysis.rawAiLabel} '
                  '(${incident.analysis.rawConfidence.toStringAsFixed(2)})',
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

          // ── AI Analysis (LLM) ─────────────────────────────────────────────
          if (incident.reportId != null) ...[
            SectionCard(
              title: 'AI Analysis',
              subtitle: incident.finalDecision.status ==
                      FinalDecisionStatus.suspicious
                  ? 'Plain-language summary and recommended investigation steps.'
                  : 'Plain-language summary of the verifier decision.',
              child: _AiAnalysisBody(
                explanation: _aiExplanation,
                recommendations: _aiRecommendations,
                loading: _aiLoading,
                isSuspicious: incident.finalDecision.status ==
                    FinalDecisionStatus.suspicious,
              ),
            ),
            const SizedBox(height: 16),
          ],

          // ── Final decision ─────────────────────────────────────────────────
          SectionCard(
            title: 'Final decision',
            subtitle: '',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(incident.finalDecision.explanation),
                const SizedBox(height: 8),
                Text(
                  'Recommended action: ${incident.finalDecision.recommendedAnalystAction}',
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // ── Analyst verdict ────────────────────────────────────────────────
          SectionCard(
            title: 'Analyst verdict',
            subtitle: incident.reportId != null
                ? 'Report #${incident.reportId} — select your verdict to train the model.'
                : 'This incident was not saved to the database (offline mode).',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (_feedbackSubmitted) ...[
                  _SubmittedBanner(verdict: _selectedVerdict!),
                  const SizedBox(height: 16),
                ],

                // 4 verdict buttons in a 2×2 grid
                GridView.count(
                  crossAxisCount: 2,
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  crossAxisSpacing: 10,
                  mainAxisSpacing: 10,
                  childAspectRatio: 2.8,
                  children: _verdicts.map((v) {
                    final selected = _selectedVerdict == v.value;
                    return _VerdictButton(
                      option: v,
                      selected: selected,
                      disabled: _feedbackSubmitted || incident.reportId == null,
                      onTap: () => setState(() => _selectedVerdict = v.value),
                    );
                  }).toList(),
                ),
                const SizedBox(height: 16),

                // Notes field
                TextField(
                  controller: _notesController,
                  minLines: 2,
                  maxLines: 4,
                  enabled: !_feedbackSubmitted,
                  decoration: const InputDecoration(
                    labelText: 'Analyst notes (optional)',
                    hintText: 'Add context, false-positive reason, or escalation note.',
                  ),
                ),
                const SizedBox(height: 14),

                // Action buttons
                Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  children: [
                    FilledButton.icon(
                      onPressed: _feedbackSubmitted ||
                              _feedbackSubmitting ||
                              _selectedVerdict == null ||
                              incident.reportId == null
                          ? null
                          : _submitFeedback,
                      icon: _feedbackSubmitting
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.send_outlined),
                      label: Text(
                        _feedbackSubmitted ? 'Verdict submitted' : 'Submit verdict',
                      ),
                    ),
                    FilledButton.icon(
                      onPressed: () {
                        widget.controller.saveAnalystNotes(
                          incident: incident,
                          analystName: 'SOC Analyst',
                          notes: _notesController.text,
                        );
                        _showSnack('Analyst notes saved.');
                      },
                      icon: const Icon(Icons.save_outlined),
                      label: const Text('Save notes'),
                      style: FilledButton.styleFrom(
                        backgroundColor: Theme.of(context).colorScheme.secondary,
                      ),
                    ),
                    OutlinedButton.icon(
                      onPressed: report == null
                          ? null
                          : () async {
                              await widget.controller.exportReport(report);
                            },
                      icon: const Icon(Icons.picture_as_pdf_outlined),
                      label: const Text('Export PDF'),
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

// ── Verdict option data ────────────────────────────────────────────────────────

class _VerdictOption {
  const _VerdictOption({
    required this.value,
    required this.label,
    required this.description,
    required this.icon,
    required this.color,
  });

  final String value;
  final String label;
  final String description;
  final IconData icon;
  final Color color;
}

// ── Verdict button ─────────────────────────────────────────────────────────────

class _VerdictButton extends StatelessWidget {
  const _VerdictButton({
    required this.option,
    required this.selected,
    required this.disabled,
    required this.onTap,
  });

  final _VerdictOption option;
  final bool selected;
  final bool disabled;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final color = disabled ? Colors.grey : option.color;
    return InkWell(
      onTap: disabled ? null : onTap,
      borderRadius: BorderRadius.circular(10),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: selected ? color.withValues(alpha: 0.12) : Colors.transparent,
          border: Border.all(
            color: selected ? color : color.withValues(alpha: 0.35),
            width: selected ? 2 : 1,
          ),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Row(
          children: [
            Icon(option.icon, color: color, size: 18),
            const SizedBox(width: 8),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    option.label,
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: color,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            if (selected)
              Icon(Icons.check_circle, color: color, size: 16),
          ],
        ),
      ),
    );
  }
}

// ── Submitted banner ───────────────────────────────────────────────────────────

class _SubmittedBanner extends StatelessWidget {
  const _SubmittedBanner({required this.verdict});

  final String verdict;

  @override
  Widget build(BuildContext context) {
    final option = _verdicts.firstWhere((v) => v.value == verdict);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: option.color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: option.color.withValues(alpha: 0.4)),
      ),
      child: Row(
        children: [
          Icon(Icons.check_circle, color: option.color, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'Verdict "${option.label}" submitted — this sample will be used for the next model fine-tune.',
              style: TextStyle(color: option.color, fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}

// ── AI Analysis body ──────────────────────────────────────────────────────────

class _AiAnalysisBody extends StatelessWidget {
  const _AiAnalysisBody({
    required this.explanation,
    required this.recommendations,
    required this.loading,
    required this.isSuspicious,
  });

  final String? explanation;
  final String? recommendations;
  final bool loading;
  final bool isSuspicious;

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final hasExplanation = explanation != null && explanation!.trim().isNotEmpty;
    final hasRecommendations =
        recommendations != null && recommendations!.trim().isNotEmpty;

    if (!hasExplanation && !hasRecommendations) {
      return Row(
        children: [
          if (loading) ...[
            const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'Generating explanation… (Ollama is working in the background)',
                style: textTheme.bodyMedium,
              ),
            ),
          ] else
            Expanded(
              child: Text(
                'No AI explanation available. Make sure the Ollama service is running.',
                style: textTheme.bodyMedium?.copyWith(color: Colors.grey),
              ),
            ),
        ],
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (hasExplanation) ...[
          Text('Explanation', style: textTheme.titleSmall),
          const SizedBox(height: 6),
          Text(explanation!.trim(), style: textTheme.bodyMedium),
        ],
        if (hasExplanation && (hasRecommendations || (loading && isSuspicious)))
          const SizedBox(height: 14),
        if (hasRecommendations) ...[
          Text(
            'Recommended investigation steps',
            style: textTheme.titleSmall,
          ),
          const SizedBox(height: 6),
          Text(recommendations!.trim(), style: textTheme.bodyMedium),
        ] else if (loading && isSuspicious) ...[
          Row(
            children: [
              const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Generating recommendations…',
                  style: textTheme.bodyMedium,
                ),
              ),
            ],
          ),
        ],
      ],
    );
  }
}

// ── Meta chip ──────────────────────────────────────────────────────────────────

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
