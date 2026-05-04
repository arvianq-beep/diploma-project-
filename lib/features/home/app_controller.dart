import 'dart:async';

import 'package:diploma_application_ml/data/repositories/ids_repository.dart';
import 'package:diploma_application_ml/domain/models/analysis_result.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/batch_analysis_summary.dart';
import 'package:diploma_application_ml/domain/models/final_decision.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/domain/models/ml_model_info.dart';
import 'package:diploma_application_ml/domain/models/realtime_event.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';
import 'package:diploma_application_ml/domain/models/verification_check.dart';
import 'package:diploma_application_ml/domain/models/verification_result.dart';
import 'package:flutter/foundation.dart';

enum AnalysisPhase { idle, rawAiRunning, verificationRunning, ready }

class AppController extends ChangeNotifier {
  AppController({required IdsRepository repository}) : _repository = repository;

  final IdsRepository _repository;

  IdsRepository get repository => _repository;

  int _tabIndex = 0;
  bool _initializing = true;
  bool _isAnalyzing = false;
  bool _isImporting = false;
  bool _isExporting = false;
  String? _error;
  String _loadingMessage = 'Processing event...';
  double? _loadingProgress;
  AnalysisPhase _analysisPhase = AnalysisPhase.idle;
  ThreatEvent? _selectedEvent;
  IncidentCase? _latestIncident;
  final List<IncidentCase> _history = [];
  final List<ReportModel> _reports = [];
  late final List<ThreatEvent> _sampleEvents;
  MlModelInfo _modelInfo = MlModelInfo.fallback();
  BatchAnalysisSummary? _lastBatchSummary;

  // Real-time monitoring state
  bool _realtimeRunning = false;
  String _realtimeSource = 'synthetic';
  final List<RealtimeEvent> _realtimeEvents = [];
  int _realtimeThreatCount = 0;
  int _realtimeBenignCount = 0;
  Timer? _realtimePoller;

  int get tabIndex => _tabIndex;
  bool get initializing => _initializing;
  bool get isAnalyzing => _isAnalyzing;
  bool get isImporting => _isImporting;
  bool get isExporting => _isExporting;
  String? get error => _error;
  String get loadingMessage => _loadingMessage;
  double? get loadingProgress => _loadingProgress;
  AnalysisPhase get analysisPhase => _analysisPhase;
  ThreatEvent? get selectedEvent => _selectedEvent;
  IncidentCase? get latestIncident => _latestIncident;
  List<IncidentCase> get history => List.unmodifiable(_history);
  List<ReportModel> get reports => List.unmodifiable(_reports);
  List<ThreatEvent> get sampleEvents => List.unmodifiable(_sampleEvents);
  MlModelInfo get modelInfo => _modelInfo;
  BatchAnalysisSummary? get lastBatchSummary => _lastBatchSummary;

  // Real-time getters
  bool get realtimeRunning => _realtimeRunning;
  String get realtimeSource => _realtimeSource;
  List<RealtimeEvent> get realtimeEvents => List.unmodifiable(_realtimeEvents);
  int get realtimeThreatCount => _realtimeThreatCount;
  int get realtimeBenignCount => _realtimeBenignCount;

  Future<List<({String value, String label})>> fetchRealtimeInterfaces(
    String source,
  ) => _repository.fetchRealtimeInterfaces(source);

  void initialize() {
    _sampleEvents = _repository.getSampleEvents();
    _selectedEvent = _sampleEvents.first;

    final seeds = _repository.getSeedIncidents();
    _history
      ..clear()
      ..addAll(seeds);
    _latestIncident = seeds.first;
    _reports
      ..clear()
      ..addAll(seeds.map(_repository.buildReport));
    _initializing = false;
    notifyListeners();
    unawaited(_loadModelInfo());
  }

  void setTabIndex(int value) {
    _tabIndex = value;
    notifyListeners();
  }

  void selectSample(ThreatEvent event) {
    _selectedEvent = event;
    notifyListeners();
  }

  Future<void> runAnalysis() async {
    final event = _selectedEvent;
    if (event == null) return;

    _error = null;
    _isAnalyzing = true;
    _isImporting = false;
    _analysisPhase = AnalysisPhase.rawAiRunning;
    _loadingProgress = null;
    _loadingMessage = 'Running raw AI analysis for the selected event.';
    notifyListeners();

    try {
      await Future<void>.delayed(const Duration(milliseconds: 500));
      _analysisPhase = AnalysisPhase.verificationRunning;
      _loadingMessage = 'Applying verification checks and preparing the final decision.';
      notifyListeners();
      await Future<void>.delayed(const Duration(milliseconds: 550));

      final incident = await _repository.analyzeEvent(event);
      _latestIncident = incident;
      _history.insert(0, incident);
      _reports.insert(0, _repository.buildReport(incident));
      _analysisPhase = AnalysisPhase.ready;
      _loadingProgress = 1;
      _loadingMessage = 'Analysis complete.';
      _tabIndex = 1;
    } catch (exception) {
      _error = exception.toString();
      _analysisPhase = AnalysisPhase.idle;
    } finally {
      _isAnalyzing = false;
      _loadingProgress = null;
      notifyListeners();
    }
  }

  Future<void> importFromFile(String path) async {
    _error = null;
    _isAnalyzing = true;
    _isImporting = true;
    _analysisPhase = AnalysisPhase.rawAiRunning;
    _loadingProgress = 0;
    _loadingMessage = 'Preparing CSV import...';
    notifyListeners();

    try {
      final incidents = await _repository.analyzeCsvFile(
        path,
        onProgress: ({
          required String phase,
          required int processed,
          required int total,
          required String message,
        }) {
          _analysisPhase = phase == 'parsing'
              ? AnalysisPhase.rawAiRunning
              : AnalysisPhase.verificationRunning;
          _loadingMessage = message;
          _loadingProgress = total > 0
              ? (processed / total).clamp(0.0, 1.0)
              : null;
          notifyListeners();
        },
      );
      if (incidents.isEmpty) {
        _error = 'No CSV rows could be parsed into ThreatEvent objects.';
        return;
      }

      _selectedEvent = incidents.first.event;
      _latestIncident = incidents.first;
      _history.insertAll(0, incidents);
      _reports.insertAll(0, incidents.map(_repository.buildReport));
      _lastBatchSummary = _repository.buildBatchSummary(path, incidents);
      _analysisPhase = AnalysisPhase.ready;
      _loadingProgress = 1;
      _loadingMessage = 'Dataset import complete.';
      _tabIndex = 1;
    } catch (exception) {
      _error = exception.toString();
      _analysisPhase = AnalysisPhase.idle;
    } finally {
      _isAnalyzing = false;
      _isImporting = false;
      _loadingProgress = null;
      notifyListeners();
    }
  }

  void submitLatestForReview() {
    final incident = _latestIncident;
    if (incident == null) return;

    final updated = _repository.updateAnalystReview(
      incident,
      analystName: 'SOC Analyst',
      notes:
          'Queued for manual review because the verification layer did not fully converge.',
      state: AnalystReviewState.pending,
    );

    _replaceIncident(updated);
  }

  void saveAnalystNotes({
    required IncidentCase incident,
    required String analystName,
    required String notes,
  }) {
    final state =
        incident.finalDecision.status == FinalDecisionStatus.suspicious
        ? AnalystReviewState.pending
        : AnalystReviewState.reviewed;
    final updated = _repository.updateAnalystReview(
      incident,
      analystName: analystName,
      notes: notes.trim().isEmpty ? incident.analystReview.notes : notes.trim(),
      state: state,
    );
    _replaceIncident(updated);
  }

  Future<String?> exportReport(ReportModel report) async {
    _isExporting = true;
    notifyListeners();

    try {
      final path = await _repository.exportReport(report);
      final updated = report.copyWith(exportedPdfPath: path);
      final index = _reports.indexWhere((item) => item.id == report.id);
      if (index != -1) {
        _reports[index] = updated;
      }
      return path;
    } catch (exception) {
      _error = exception.toString();
      return null;
    } finally {
      _isExporting = false;
      notifyListeners();
    }
  }

  ReportModel? reportForIncident(IncidentCase incident) {
    for (final report in _reports) {
      if (report.incident.event.id == incident.event.id) {
        return report;
      }
    }
    return null;
  }

  void clearError() {
    _error = null;
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Real-time monitoring
  // ---------------------------------------------------------------------------

  Future<void> startRealtime({
    String source = 'synthetic',
    int batchSize = 32,
    String? interface,
  }) async {
    if (_realtimeRunning) return;
    _error = null;
    _realtimeSource = source;
    _realtimeEvents.clear();
    _realtimeThreatCount = 0;
    _realtimeBenignCount = 0;
    notifyListeners();

    try {
      await _repository.startRealtime(
        source: source,
        batchSize: batchSize,
        interface: interface,
      );
      _realtimeRunning = true;
      // Poll for new results every second
      _realtimePoller = Timer.periodic(
        const Duration(seconds: 1),
        (_) => _pollRealtimeResults(),
      );
      notifyListeners();
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }

  Future<void> stopRealtime() async {
    _realtimePoller?.cancel();
    _realtimePoller = null;
    try {
      await _repository.stopRealtime();
    } catch (_) {}
    _realtimeRunning = false;
    notifyListeners();
  }

  Future<void> _pollRealtimeResults() async {
    try {
      final (:events, :running) = await _repository.pollRealtimeResults();
      if (events.isNotEmpty) {
        _realtimeEvents.insertAll(0, events);
        if (_realtimeEvents.length > 500) {
          _realtimeEvents.removeRange(500, _realtimeEvents.length);
        }
        for (final e in events) {
          if (e.isThreat) {
            _realtimeThreatCount++;
          } else {
            _realtimeBenignCount++;
          }
          // Convert to IncidentCase so Dashboard/Analysis/Reports update automatically
          final incident = _realtimeEventToIncident(e);
          _history.insert(0, incident);
          _latestIncident = incident;
          _reports.insert(0, _repository.buildReport(incident));
        }
        notifyListeners();
      }
      if (_realtimeRunning != running) {
        _realtimeRunning = running;
        if (!running) {
          _realtimePoller?.cancel();
          _realtimePoller = null;
        }
        notifyListeners();
      }
    } catch (_) {
      // Silently ignore poll errors — backend may be temporarily unreachable
    }
  }

  /// Convert a lean RealtimeEvent into a full IncidentCase so it feeds
  /// Dashboard charts, Analysis latest result, and Reports list.
  IncidentCase _realtimeEventToIncident(RealtimeEvent e) {
    final status = switch (e.finalStatus) {
      'Verified Threat' => FinalDecisionStatus.verifiedThreat,
      'Suspicious'      => FinalDecisionStatus.suspicious,
      _                 => FinalDecisionStatus.benign,
    };

    final proto = switch (e.proto) {
      6  => 'TCP',
      17 => 'UDP',
      1  => 'ICMP',
      _  => 'PROTO/${e.proto}',
    };

    final event = ThreatEvent(
      id: 'rt-${e.processedAt.millisecondsSinceEpoch}',
      title: '[RT] ${e.srcIp}:${e.srcPort} → ${e.dstIp}:${e.dstPort}',
      description:
          'Real-time flow: $proto  |  status: ${e.finalStatus}  |  '
          'det: ${e.detectorLabel} (${(e.detectorConfidence * 100).toStringAsFixed(0)}%)',
      sourceIp: e.srcIp,
      destinationIp: e.dstIp,
      sourcePort: e.srcPort,
      destinationPort: e.dstPort,
      protocol: proto,
      bytesTransferredKb: 0,
      durationSeconds: 0,
      packetsPerSecond: 0,
      failedLogins: 0,
      anomalyScore: e.detectorConfidence,
      contextRiskScore: e.verificationConfidence,
      knownBadSource: false,
      offHoursActivity: false,
      repeatedAttempts: false,
      sampleSource: 'realtime',
      capturedAt: e.processedAt,
      tags: ['realtime', e.finalStatus.toLowerCase().replaceAll(' ', '-')],
    );

    final analysis = AnalysisResult(
      rawAiLabel: e.detectorLabel,
      rawConfidence: e.detectorConfidence,
      stabilityScore: e.detectorStability,
      modelVersion: 'rf-flow-77 (realtime)',
      reasoning: e.triggeredIndicators.isEmpty
          ? 'No specific indicators triggered.'
          : 'Triggered: ${e.triggeredIndicators.join(', ')}.',
      alternativeHypothesis: e.detectorLabel == 'Benign'
          ? 'Could be low-volume attack below detection threshold.'
          : 'Could be legitimate high-rate background traffic.',
      triggeredIndicators: e.triggeredIndicators,
    );

    final checks = e.verificationChecks.map((raw) {
      return VerificationCheck(
        key: (raw['key'] ?? '').toString(),
        title: (raw['title'] ?? '').toString(),
        description: (raw['description'] ?? '').toString(),
        passed: raw['passed'] == true,
        score: (raw['score'] as num?)?.toDouble() ?? 0.0,
        weight: (raw['weight'] as num?)?.toDouble() ?? 0.0,
        evidence: ((raw['evidence'] as List?) ?? const [])
            .map((e) => e.toString())
            .toList(),
      );
    }).toList();

    final verification = VerificationResult(
      checks: checks,
      passed: e.isVerifiedThreat,
      verificationScore: e.verificationConfidence,
      explanationNotes: [
        'Two-stage pipeline: RF detector + MLP verifier.',
        'Verifier model: verifier-tabular-mlp (realtime)',
      ],
      summary: e.verificationSummary.isNotEmpty
          ? e.verificationSummary
          : '${e.finalStatus}: ${e.recommendedAction}',
    );

    final finalDecision = FinalDecision(
      rawAiLabel: e.detectorLabel,
      rawConfidence: e.detectorConfidence,
      verificationChecks: const [],
      status: status,
      explanation:
          'Realtime flow classified as ${e.finalStatus}. '
          'Detector confidence ${(e.detectorConfidence * 100).toStringAsFixed(0)}%, '
          'verifier confidence ${(e.verificationConfidence * 100).toStringAsFixed(0)}%.',
      timestamp: e.processedAt,
      recommendedAnalystAction: e.recommendedAction,
    );

    return IncidentCase(
      event: event,
      analysis: analysis,
      verification: verification,
      finalDecision: finalDecision,
      reportId: e.reportId,
      explanationPending: e.explanationPending,
      analystReview: AnalystReview(
        state: status == FinalDecisionStatus.suspicious
            ? AnalystReviewState.pending
            : AnalystReviewState.reviewed,
        analystName: 'Realtime Monitor',
        notes: '',
        updatedAt: e.processedAt,
      ),
    );
  }

  @override
  void dispose() {
    _realtimePoller?.cancel();
    super.dispose();
  }

  Map<FinalDecisionStatus, int> get statusCounts {
    final counts = <FinalDecisionStatus, int>{
      FinalDecisionStatus.benign: 0,
      FinalDecisionStatus.verifiedThreat: 0,
      FinalDecisionStatus.suspicious: 0,
    };

    for (final incident in _history) {
      counts[incident.finalDecision.status] =
          (counts[incident.finalDecision.status] ?? 0) + 1;
    }

    return counts;
  }

  List<IncidentCase> get recentIncidents => _history.take(6).toList();

  Future<void> _loadModelInfo() async {
    _modelInfo = await _repository.fetchModelInfo();
    notifyListeners();
  }

  void _replaceIncident(IncidentCase updated) {
    final historyIndex = _history.indexWhere(
      (item) => item.event.id == updated.event.id,
    );
    if (historyIndex != -1) {
      _history[historyIndex] = updated;
    }

    if (_latestIncident?.event.id == updated.event.id) {
      _latestIncident = updated;
    }

    final reportIndex = _reports.indexWhere(
      (item) => item.incident.event.id == updated.event.id,
    );
    if (reportIndex != -1) {
      _reports[reportIndex] = _reports[reportIndex].copyWith(
        incident: updated,
        summary:
            '${updated.finalDecision.status.label}: ${updated.event.title}. ${updated.finalDecision.explanation}',
        status: updated.finalDecision.status,
      );
    }

    notifyListeners();
  }
}
