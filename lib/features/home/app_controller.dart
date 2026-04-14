import 'dart:async';

import 'package:diploma_application_ml/data/repositories/ids_repository.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/batch_analysis_summary.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/domain/models/ml_model_info.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';
import 'package:flutter/foundation.dart';

enum AnalysisPhase { idle, rawAiRunning, verificationRunning, ready }

class AppController extends ChangeNotifier {
  AppController({required IdsRepository repository}) : _repository = repository;

  final IdsRepository _repository;

  int _tabIndex = 0;
  bool _initializing = true;
  bool _isAnalyzing = false;
  bool _isImporting = false;
  bool _isPickingDataset = false;
  bool _isExporting = false;
  String? _error;
  AnalysisPhase _analysisPhase = AnalysisPhase.idle;
  ThreatEvent? _selectedEvent;
  IncidentCase? _latestIncident;
  final List<IncidentCase> _history = [];
  final List<ReportModel> _reports = [];
  late final List<ThreatEvent> _sampleEvents;
  MlModelInfo _modelInfo = MlModelInfo.fallback();
  BatchAnalysisSummary? _lastBatchSummary;

  int get tabIndex => _tabIndex;
  bool get initializing => _initializing;
  bool get isAnalyzing => _isAnalyzing;
  bool get isImporting => _isImporting;
  bool get isPickingDataset => _isPickingDataset;
  bool get isDatasetBusy => _isPickingDataset || _isImporting;
  bool get isWorking => _isAnalyzing || _isPickingDataset;
  bool get isExporting => _isExporting;
  String? get error => _error;
  AnalysisPhase get analysisPhase => _analysisPhase;
  ThreatEvent? get selectedEvent => _selectedEvent;
  IncidentCase? get latestIncident => _latestIncident;
  List<IncidentCase> get history => List.unmodifiable(_history);
  List<ReportModel> get reports => List.unmodifiable(_reports);
  List<ThreatEvent> get sampleEvents => List.unmodifiable(_sampleEvents);
  MlModelInfo get modelInfo => _modelInfo;
  BatchAnalysisSummary? get lastBatchSummary => _lastBatchSummary;

  String get loadingMessage {
    if (_isPickingDataset) {
      return 'Preparing dataset import and waiting for the CSV file selection.';
    }

    if (_isImporting) {
      return 'Importing CSV dataset and analyzing events. This can take a few seconds.';
    }

    switch (_analysisPhase) {
      case AnalysisPhase.rawAiRunning:
        return 'Running raw AI analysis for the selected event.';
      case AnalysisPhase.verificationRunning:
        return 'Applying verification checks and preparing the final decision.';
      case AnalysisPhase.ready:
      case AnalysisPhase.idle:
        return 'Processing event...';
    }
  }

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

  void beginDatasetSelection() {
    if (_isPickingDataset) return;
    _error = null;
    _isPickingDataset = true;
    notifyListeners();
  }

  void endDatasetSelection() {
    if (!_isPickingDataset) return;
    _isPickingDataset = false;
    notifyListeners();
  }

  Future<void> runAnalysis() async {
    final event = _selectedEvent;
    if (event == null) return;

    _error = null;
    _isAnalyzing = true;
    _isImporting = false;
    _analysisPhase = AnalysisPhase.rawAiRunning;
    notifyListeners();

    try {
      await Future<void>.delayed(const Duration(milliseconds: 500));
      _analysisPhase = AnalysisPhase.verificationRunning;
      notifyListeners();
      await Future<void>.delayed(const Duration(milliseconds: 550));

      final incident = await _repository.analyzeEvent(event);
      _latestIncident = incident;
      _history.insert(0, incident);
      _reports.insert(0, _repository.buildReport(incident));
      _analysisPhase = AnalysisPhase.ready;
      _tabIndex = 1;
    } catch (exception) {
      _error = exception.toString();
      _analysisPhase = AnalysisPhase.idle;
    } finally {
      _isAnalyzing = false;
      notifyListeners();
    }
  }

  Future<void> importFromFile(String path) async {
    _error = null;
    _isAnalyzing = true;
    _isImporting = true;
    _analysisPhase = AnalysisPhase.rawAiRunning;
    notifyListeners();

    try {
      final incidents = await _repository.analyzeCsvFile(path);
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
      _tabIndex = 1;
    } catch (exception) {
      _error = exception.toString();
      _analysisPhase = AnalysisPhase.idle;
    } finally {
      _isAnalyzing = false;
      _isImporting = false;
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
