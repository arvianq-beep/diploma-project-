import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/incident_case.dart';

class ReportModel {
  final String id;
  final IncidentCase incident;
  final DateTime generatedAt;
  final String summary;
  final FinalDecisionStatus status;
  final String? exportedPdfPath;

  const ReportModel({
    required this.id,
    required this.incident,
    required this.generatedAt,
    required this.summary,
    required this.status,
    this.exportedPdfPath,
  });

  ReportModel copyWith({
    String? id,
    IncidentCase? incident,
    DateTime? generatedAt,
    String? summary,
    FinalDecisionStatus? status,
    String? exportedPdfPath,
  }) {
    return ReportModel(
      id: id ?? this.id,
      incident: incident ?? this.incident,
      generatedAt: generatedAt ?? this.generatedAt,
      summary: summary ?? this.summary,
      status: status ?? this.status,
      exportedPdfPath: exportedPdfPath ?? this.exportedPdfPath,
    );
  }
}
