import 'package:diploma_application_ml/data/repositories/mock_ids_repository.dart';
import 'package:diploma_application_ml/data/services/csv_event_import_service.dart';
import 'package:diploma_application_ml/data/services/ids_api_service.dart';
import 'package:diploma_application_ml/data/services/report_export_service.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/batch_analysis_summary.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/domain/models/ml_model_info.dart';
import 'package:diploma_application_ml/domain/models/realtime_event.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';

typedef CsvAnalysisProgressCallback =
    void Function({
      required String phase,
      required int processed,
      required int total,
      required String message,
    });

class IdsRepository {
  IdsRepository({
    MockIdsRepository? fallbackRepository,
    IdsApiService? apiService,
    CsvEventImportService? csvImportService,
    ReportExportService? reportExportService,
  }) : _fallbackRepository = fallbackRepository ?? MockIdsRepository(),
       _apiService = apiService ?? IdsApiService(),
       _csvImportService = csvImportService ?? CsvEventImportService(),
       _reportExportService =
           reportExportService ?? const ReportExportService();

  final MockIdsRepository _fallbackRepository;
  final IdsApiService _apiService;
  final CsvEventImportService _csvImportService;
  final ReportExportService _reportExportService;

  List<ThreatEvent> getSampleEvents() => _fallbackRepository.getSampleEvents();

  List<IncidentCase> getSeedIncidents() =>
      _fallbackRepository.getSeedIncidents();

  Future<MlModelInfo> fetchModelInfo() async {
    try {
      return await _apiService.fetchModelInfo();
    } catch (_) {
      return MlModelInfo.fallback();
    }
  }

  Future<IncidentCase> analyzeEvent(ThreatEvent event) async {
    try {
      return await _apiService.analyzeEvent(event);
    } catch (_) {
      return _fallbackRepository.analyzeEvent(event);
    }
  }

  Future<List<ThreatEvent>> importThreatEvents(
    String path, {
    int? limit,
    CsvAnalysisProgressCallback? onProgress,
  }) {
    return _csvImportService.parseFile(
      path,
      limit: limit,
      onProgress: ({
        required int rowsParsed,
        required int? totalRowsEstimate,
        required String message,
      }) {
        onProgress?.call(
          phase: 'parsing',
          processed: rowsParsed,
          total: totalRowsEstimate ?? rowsParsed,
          message: message,
        );
      },
    );
  }

  Future<List<IncidentCase>> analyzeCsvFile(
    String path, {
    int limit = 30,
    CsvAnalysisProgressCallback? onProgress,
  }) async {
    final events = await importThreatEvents(
      path,
      limit: limit,
      onProgress: onProgress,
    );
    final sliced = events.take(limit).toList();
    final incidents = <IncidentCase>[];
    if (sliced.isEmpty) {
      onProgress?.call(
        phase: 'parsing',
        processed: 0,
        total: 0,
        message: 'No events found in CSV file.',
      );
      return incidents;
    }

    onProgress?.call(
      phase: 'analyzing',
      processed: 0,
      total: sliced.length,
      message: 'Starting backend analysis for ${sliced.length} events...',
    );

    for (final event in sliced) {
      incidents.add(await analyzeEvent(event));
      onProgress?.call(
        phase: 'analyzing',
        processed: incidents.length,
        total: sliced.length,
        message: 'Analyzing events: ${incidents.length} / ${sliced.length}',
      );
      await Future<void>.delayed(Duration.zero);
    }
    return incidents;
  }

  BatchAnalysisSummary buildBatchSummary(
    String sourceName,
    List<IncidentCase> incidents,
  ) {
    var benign = 0;
    var verifiedThreat = 0;
    var suspicious = 0;

    for (final incident in incidents) {
      switch (incident.finalDecision.status) {
        case FinalDecisionStatus.benign:
          benign++;
        case FinalDecisionStatus.verifiedThreat:
          verifiedThreat++;
        case FinalDecisionStatus.suspicious:
          suspicious++;
      }
    }

    return BatchAnalysisSummary(
      sourceName: sourceName,
      processed: incidents.length,
      benign: benign,
      verifiedThreat: verifiedThreat,
      suspicious: suspicious,
      generatedAt: DateTime.now(),
    );
  }

  ReportModel buildReport(IncidentCase incident) =>
      _fallbackRepository.buildReport(incident);

  Future<String> exportReport(ReportModel report) {
    return _reportExportService.exportReport(report);
  }

  // ---------------------------------------------------------------------------
  // Real-time monitoring
  // ---------------------------------------------------------------------------

  Future<void> startRealtime({
    String source = 'synthetic',
    int batchSize = 32,
    double rateLimit = 0.05,
    String? interface,
  }) {
    return _apiService.startRealtime(
      source: source,
      batchSize: batchSize,
      rateLimit: rateLimit,
      interface: interface,
    );
  }

  Future<void> stopRealtime() => _apiService.stopRealtime();

  Future<List<({String value, String label})>> fetchRealtimeInterfaces(
    String source,
  ) => _apiService.fetchRealtimeInterfaces(source);

  Future<({List<RealtimeEvent> events, bool running})> pollRealtimeResults() =>
      _apiService.pollRealtimeResults();

  IncidentCase updateAnalystReview(
    IncidentCase incident, {
    required String analystName,
    required String notes,
    required AnalystReviewState state,
  }) {
    return _fallbackRepository.updateAnalystReview(
      incident,
      analystName: analystName,
      notes: notes,
      state: state,
    );
  }

  Future<void> submitAnalystFeedback({
    required int reportId,
    required String verdict,
    String? notes,
  }) {
    return _apiService.submitAnalystFeedback(
      reportId: reportId,
      verdict: verdict,
      notes: notes,
    );
  }
}
