import 'dart:io';

import 'package:diploma_application_ml/data/services/ai_analysis_service.dart';
import 'package:diploma_application_ml/data/services/report_export_service.dart';
import 'package:diploma_application_ml/data/services/sample_event_service.dart';
import 'package:diploma_application_ml/data/services/verification_service.dart';
import 'package:diploma_application_ml/domain/models/analyst_review.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:diploma_application_ml/domain/models/threat_event.dart';

class MockIdsRepository {
  MockIdsRepository({
    SampleEventService? sampleService,
    AiAnalysisService? aiService,
    VerificationService? verificationService,
    ReportExportService? reportExportService,
  }) : _sampleService = sampleService ?? SampleEventService(),
       _aiService = aiService ?? const AiAnalysisService(),
       _verificationService =
           verificationService ?? const VerificationService(),
       _reportExportService =
           reportExportService ?? const ReportExportService();

  final SampleEventService _sampleService;
  final AiAnalysisService _aiService;
  final VerificationService _verificationService;
  final ReportExportService _reportExportService;

  List<ThreatEvent> getSampleEvents() => _sampleService.getSamples();

  List<IncidentCase> getSeedIncidents() {
    final samples = getSampleEvents();
    return samples.take(4).map(_buildIncident).toList();
  }

  IncidentCase analyzeEvent(ThreatEvent event) => _buildIncident(event);

  ReportModel buildReport(IncidentCase incident) {
    return ReportModel(
      id: 'report-${incident.event.id}',
      incident: incident,
      generatedAt: DateTime.now(),
      summary:
          '${incident.finalDecision.status.label}: ${incident.event.title}. ${incident.finalDecision.explanation}',
      status: incident.finalDecision.status,
    );
  }

  Future<String> exportReport(ReportModel report) {
    return _reportExportService.exportReport(report);
  }

  ThreatEvent createEventFromFile(String path) {
    final file = File(path);
    final fileName = file.uri.pathSegments.isEmpty
        ? 'imported_event'
        : file.uri.pathSegments.last;
    final size = file.existsSync() ? file.lengthSync() : 0;
    final hash = fileName.codeUnits.fold<int>(size, (sum, item) => sum + item);

    return ThreatEvent(
      id: 'file-${hash % 10000}',
      title: 'Imported sample: $fileName',
      description:
          'Event synthesized from imported file metadata for offline diploma demonstration.',
      sourceIp: '172.16.${hash % 20}.${(hash % 200) + 10}',
      destinationIp: '10.0.${hash % 10}.${(hash % 150) + 20}',
      sourcePort: 40000 + (hash % 2000),
      destinationPort: 443,
      protocol: hash.isEven ? 'TCP' : 'UDP',
      bytesTransferredKb: 120 + (size / 1024),
      durationSeconds: 5 + ((hash % 50) / 2),
      packetsPerSecond: 80 + (hash % 700),
      failedLogins: hash % 9,
      anomalyScore: ((hash % 100) / 100).clamp(0.18, 0.93),
      contextRiskScore: (((hash ~/ 3) % 100) / 100).clamp(0.16, 0.89),
      knownBadSource: hash % 5 == 0,
      offHoursActivity: hash % 4 == 0,
      repeatedAttempts: hash % 3 == 0,
      sampleSource: 'Imported File',
      capturedAt: DateTime.now(),
      tags: const ['imported', 'offline-demo'],
    );
  }

  IncidentCase updateAnalystReview(
    IncidentCase incident, {
    required String analystName,
    required String notes,
    required AnalystReviewState state,
  }) {
    return incident.copyWith(
      analystReview: incident.analystReview.copyWith(
        analystName: analystName,
        notes: notes,
        state: state,
        updatedAt: DateTime.now(),
      ),
    );
  }

  IncidentCase _buildIncident(ThreatEvent event) {
    final analysis = _aiService.analyze(event);
    final verification = _verificationService.verify(
      event: event,
      analysis: analysis,
    );

    return IncidentCase(
      event: event,
      analysis: analysis,
      verification: verification.verification,
      finalDecision: verification.decision,
      analystReview: AnalystReview(
        state: verification.decision.status == FinalDecisionStatus.suspicious
            ? AnalystReviewState.pending
            : AnalystReviewState.reviewed,
        analystName: 'SOC Analyst',
        notes: verification.decision.status == FinalDecisionStatus.suspicious
            ? 'Awaiting analyst validation of conflicting evidence.'
            : 'Automated workflow completed with no manual intervention required.',
        updatedAt: DateTime.now(),
      ),
    );
  }
}
