import 'dart:io';

import 'package:diploma_application_ml/core/utils/formatters.dart';
import 'package:diploma_application_ml/domain/models/final_decision_status.dart';
import 'package:diploma_application_ml/domain/models/report_model.dart';
import 'package:open_file/open_file.dart';
import 'package:path_provider/path_provider.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';

class ReportExportService {
  const ReportExportService();

  // Helvetica (the pdf package default) has no Unicode support.
  // Replace known non-ASCII symbols with ASCII equivalents so characters
  // like →, —, ≥, ≤ don't disappear silently in the generated PDF.
  // Truncate evidence list: keep up to 3 items, max 60 chars each.
  static String _evidence(List<String> items) {
    const maxItems = 3;
    const maxChars = 60;
    final truncated = items.take(maxItems).map((e) {
      final s = _s(e);
      return s.length > maxChars ? '${s.substring(0, maxChars)}...' : s;
    }).toList();
    if (items.length > maxItems) {
      truncated.add('+${items.length - maxItems} more');
    }
    return truncated.join('\n');
  }

  static String _s(String text) {
    return text
        .replaceAll('→', '->')
        .replaceAll('←', '<-')
        .replaceAll('—', '--')
        .replaceAll('–', '-')
        .replaceAll('≥', '>=')
        .replaceAll('≤', '<=')
        .replaceAll('≠', '!=')
        .replaceAll('…', '...')
        .replaceAll(' ', ' '); // non-breaking space
  }

  Future<String> exportReport(ReportModel report) async {
    // Load TTF fonts so the pdf package stops using Helvetica (no Unicode).
    final fontRegular = await PdfGoogleFonts.robotoRegular();
    final fontBold    = await PdfGoogleFonts.robotoBold();

    final document = pw.Document(
      theme: pw.ThemeData.withFont(
        base: fontRegular,
        bold: fontBold,
      ),
    );
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
            pw.Text(_s(report.summary)),
            pw.SizedBox(height: 16),
            pw.Text(
              'Event metadata',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.Bullet(text: 'Event ID: ${_s(incident.event.id)}'),
            pw.Bullet(text: 'Event title: ${_s(incident.event.title)}'),
            pw.Bullet(
              text: 'Captured at: ${formatDateTime(incident.event.capturedAt)}',
            ),
            pw.Bullet(
              text: 'Source: ${incident.event.sourceIp}:${incident.event.sourcePort}',
            ),
            pw.Bullet(
              text: 'Destination: ${incident.event.destinationIp}:${incident.event.destinationPort}',
            ),
            pw.Bullet(text: 'Protocol: ${incident.event.protocol}'),
            pw.Bullet(text: 'Sample source: ${_s(incident.event.sampleSource)}'),
            pw.SizedBox(height: 16),
            pw.Text(
              'Raw AI result',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.Bullet(text: 'Label: ${incident.analysis.rawAiLabel}'),
            pw.Bullet(
              text: 'Confidence: ${incident.analysis.rawConfidence.toStringAsFixed(2)}',
            ),
            pw.Bullet(text: 'Model version: ${incident.analysis.modelVersion}'),
            pw.Bullet(
              text: 'Stability score: ${incident.analysis.stabilityScore.toStringAsFixed(2)}',
            ),
            pw.Bullet(text: 'Reasoning: ${_s(incident.analysis.reasoning)}'),
            pw.Bullet(
              text: 'Alternative hypothesis: ${_s(incident.analysis.alternativeHypothesis)}',
            ),
            pw.SizedBox(height: 16),
            pw.Text(
              'Verification checks',
              style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
            ),
            pw.TableHelper.fromTextArray(
              headers: const ['Check', 'Pass', 'Score', 'Evidence'],
              // Pass and Score get fixed widths; Check and Evidence share
              // the rest with a 3:4 ratio so evidence stays readable.
              columnWidths: {
                0: const pw.FlexColumnWidth(3),
                1: const pw.FixedColumnWidth(42),
                2: const pw.FixedColumnWidth(38),
                3: const pw.FlexColumnWidth(4),
              },
              data: incident.verification.checks
                  .map(
                    (check) => [
                      _s(check.title),
                      check.passed ? 'Passed' : 'Failed',
                      check.score.toStringAsFixed(2),
                      _evidence(check.evidence),
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
              text: 'Decision time: ${formatDateTime(incident.finalDecision.timestamp)}',
            ),
            pw.Bullet(
              text: 'Explanation: ${_s(incident.finalDecision.explanation)}',
            ),
            pw.Bullet(
              text: 'Recommended action: ${_s(incident.finalDecision.recommendedAnalystAction)}',
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
            pw.Bullet(text: 'Notes: ${_s(incident.analystReview.notes)}'),
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
