import 'package:diploma_application_ml/data/repositories/mock_ids_repository.dart';
import 'package:diploma_application_ml/data/services/csv_event_import_service.dart';
import 'package:diploma_application_ml/data/services/ids_api_service.dart';
import 'package:diploma_application_ml/data/services/report_export_service.dart';
import 'package:diploma_application_ml/data/services/verification_service.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/batch_analysis_summary.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/domain/models/ml_model_info.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';

class IdsRepository {
  IdsRepository({
    MockIdsRepository? fallbackRepository,
    IdsApiService? apiService,
    CsvEventImportService? csvImportService,
    VerificationService? verificationService,
    ReportExportService? reportExportService,
  }) : _fallbackRepository = fallbackRepository ?? MockIdsRepository(),
       _apiService = apiService ?? IdsApiService(),
       _csvImportService = csvImportService ?? CsvEventImportService(),
       _verificationService =
           verificationService ?? const VerificationService(),
       _reportExportService =
           reportExportService ?? const ReportExportService();

  final MockIdsRepository _fallbackRepository;
  final IdsApiService _apiService;
  final CsvEventImportService _csvImportService;
  final VerificationService _verificationService;
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
      final analysis = await _apiService.analyzeEvent(event);
      final verification = _verificationService.verify(
        event: event,
        analysis: analysis,
      );

      return IncidentCase(
        event: event,
        analysis: analysis,
        verification: verification.verification,
        finalDecision: verification.decision,
        analystReview: _initialReviewFor(verification.decision.status),
      );
    } catch (_) {
      return _fallbackRepository.analyzeEvent(event);
    }
  }

  Future<List<ThreatEvent>> importThreatEvents(String path) {
    return _csvImportService.parseFile(path);
  }

  Future<List<IncidentCase>> analyzeCsvFile(
    String path, {
    int limit = 30,
  }) async {
    final events = await importThreatEvents(path);
    final sliced = events.take(limit).toList();
    final incidents = <IncidentCase>[];
    for (final event in sliced) {
      incidents.add(await analyzeEvent(event));
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

  AnalystReview _initialReviewFor(FinalDecisionStatus status) {
    return AnalystReview(
      state: status == FinalDecisionStatus.suspicious
          ? AnalystReviewState.pending
          : AnalystReviewState.reviewed,
      analystName: 'SOC Analyst',
      notes: status == FinalDecisionStatus.suspicious
          ? 'Awaiting analyst validation of conflicting evidence.'
          : 'Automated workflow completed with model-backed verification.',
      updatedAt: DateTime.now(),
    );
  }
}
