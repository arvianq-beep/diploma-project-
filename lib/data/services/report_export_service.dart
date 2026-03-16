import 'dart:io';

import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:open_file/open_file.dart';
import 'package:path_provider/path_provider.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;

class ReportExportService {
  const ReportExportService();

  Future<String> exportReport(ReportModel report) async {
    final document = pw.Document();
    final incident = report.incident;

    document.addPage(
      pw.MultiPage(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.all(28),
        build: (context) {
          return [
            pw.Text(
              'AI-driven Intrusion Detection System with Verification Layer',
              style: pw.TextStyle(fontSize: 20, fontWeight: pw.FontWeight.bold),
            ),
            pw.SizedBox(height: 6),
            pw.Text('Diploma prototype report'),
            pw.SizedBox(height: 16),
            pw.Text(
              'Report summary',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.Text(report.summary),
            pw.SizedBox(height: 16),
            pw.Text(
              'Event metadata',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.Bullet(text: 'Event ID: ${incident.event.id}'),
            pw.Bullet(text: 'Event title: ${incident.event.title}'),
            pw.Bullet(
              text: 'Captured at: ${formatDateTime(incident.event.capturedAt)}',
            ),
            pw.Bullet(
              text:
                  'Source: ${incident.event.sourceIp}:${incident.event.sourcePort}',
            ),
            pw.Bullet(
              text:
                  'Destination: ${incident.event.destinationIp}:${incident.event.destinationPort}',
            ),
            pw.Bullet(text: 'Protocol: ${incident.event.protocol}'),
            pw.Bullet(text: 'Sample source: ${incident.event.sampleSource}'),
            pw.SizedBox(height: 16),
            pw.Text(
              'Raw AI result',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.Bullet(text: 'Label: ${incident.analysis.rawAiLabel}'),
            pw.Bullet(
              text:
                  'Confidence: ${formatPercent(incident.analysis.rawConfidence)}',
            ),
            pw.Bullet(text: 'Model version: ${incident.analysis.modelVersion}'),
            pw.Bullet(
              text:
                  'Stability score: ${incident.analysis.stabilityScore.toStringAsFixed(2)}',
            ),
            pw.Bullet(text: 'Reasoning: ${incident.analysis.reasoning}'),
            pw.Bullet(
              text:
                  'Alternative hypothesis: ${incident.analysis.alternativeHypothesis}',
            ),
            pw.SizedBox(height: 16),
            pw.Text(
              'Verification checks',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.TableHelper.fromTextArray(
              headers: const ['Check', 'Pass', 'Score', 'Evidence'],
              data: incident.verification.checks
                  .map(
                    (check) => [
                      check.title,
                      check.passed ? 'Passed' : 'Failed',
                      check.score.toStringAsFixed(2),
                      check.evidence.join(' | '),
                    ],
                  )
                  .toList(),
              headerDecoration: const pw.BoxDecoration(
                color: PdfColors.blueGrey800,
              ),
              headerStyle: pw.TextStyle(
                color: PdfColors.white,
                fontWeight: pw.FontWeight.bold,
              ),
              cellStyle: const pw.TextStyle(fontSize: 9),
              cellAlignment: pw.Alignment.centerLeft,
            ),
            pw.SizedBox(height: 16),
            pw.Text(
              'Final decision',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.Bullet(text: 'Status: ${incident.finalDecision.status.label}'),
            pw.Bullet(
              text:
                  'Decision time: ${formatDateTime(incident.finalDecision.timestamp)}',
            ),
            pw.Bullet(
              text: 'Explanation: ${incident.finalDecision.explanation}',
            ),
            pw.Bullet(
              text:
                  'Recommended action: ${incident.finalDecision.recommendedAnalystAction}',
            ),
            pw.SizedBox(height: 16),
            pw.Text(
              'Analyst review',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.Bullet(
              text: 'Review state: ${incident.analystReview.state.name}',
            ),
            pw.Bullet(text: 'Analyst: ${incident.analystReview.analystName}'),
            pw.Bullet(text: 'Notes: ${incident.analystReview.notes}'),
          ];
        },
      ),
    );

    final directory = await getApplicationDocumentsDirectory();
    final file = File('${directory.path}/${report.id}.pdf');
    await file.writeAsBytes(await document.save());
    await OpenFile.open(file.path);
    return file.path;
  }
}
