import 'dart:io';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:path_provider/path_provider.dart';
import 'package:open_file/open_file.dart';
import '../models/threat_model.dart';

class ReportService {
  static Future<void> generateAndOpenReport(List<ThreatLog> logs) async {
    final pdf = pw.Document();
    final now = DateTime.now();

    // Фильтруем, чтобы в отчет попали только угрозы (без чистого трафика)
    final threats = logs.where((l) => l.isThreat).toList();

    // Загружаем шрифт (стандартный Helvetica)
    final font = pw.Font.helvetica();
    final boldFont = pw.Font.helveticaBold();

    pdf.addPage(
      pw.MultiPage(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.all(32),
        build: (context) => [
          // Шапка отчета
          pw.Header(
            level: 0,
            child: pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
              children: [
                pw.Text(
                  "IITU CyberGuard Report",
                  style: pw.TextStyle(
                    font: boldFont,
                    fontSize: 24,
                    color: PdfColors.indigo900,
                  ),
                ),
                pw.Text(
                  "Generated: ${now.toString().substring(0, 19)}",
                  style: pw.TextStyle(
                    font: font,
                    fontSize: 12,
                    color: PdfColors.grey,
                  ),
                ),
              ],
            ),
          ),

          pw.SizedBox(height: 20),

          pw.Text(
            "Incident Summary",
            style: pw.TextStyle(font: boldFont, fontSize: 18),
          ),
          pw.Paragraph(
            text:
                "This document contains a verified list of cyber threats detected by the AI Secure Decision System. Please review the 'Verification' column for potential adversarial attacks.",
          ),

          pw.SizedBox(height: 10),

          // Таблица данных
          pw.TableHelper.fromTextArray(
            border: pw.TableBorder.all(color: PdfColors.grey300),
            headerStyle: pw.TextStyle(font: boldFont, color: PdfColors.white),
            headerDecoration: const pw.BoxDecoration(color: PdfColors.indigo),
            cellHeight: 30,
            cellAlignments: {
              0: pw.Alignment.centerLeft,
              1: pw.Alignment.centerLeft,
              2: pw.Alignment.centerLeft,
              3: pw.Alignment.center,
              4: pw.Alignment.center,
            },
            headers: [
              'Time',
              'Source IP',
              'Threat Type',
              'Confidence',
              'Status',
            ],
            data: List<List<String>>.generate(threats.length, (index) {
              final log = threats[index];
              return [
                log.timestamp,
                log.sourceIp,
                log.threatType,
                "${(log.aiConfidence * 100).toStringAsFixed(1)}%",
                log.isVerified ? "CONFIRMED" : "ADVERSARIAL SUSPICION",
              ];
            }),
          ),

          pw.SizedBox(height: 20),

          // Футер (подпись)
          pw.Footer(
            title: pw.Text(
              "Automated Report by Secure Decision AI Model",
              style: pw.TextStyle(
                font: font,
                fontSize: 10,
                color: PdfColors.grey,
              ),
            ),
          ),
        ],
      ),
    );

    // Сохранение файла
    try {
      final output = await getApplicationDocumentsDirectory();
      final file = File(
        "${output.path}/CyberGuard_Report_${now.millisecondsSinceEpoch}.pdf",
      );
      await file.writeAsBytes(await pdf.save());

      // Открытие файла сразу после создания
      await OpenFile.open(file.path);
    } catch (e) {
      print("Error saving PDF: $e");
    }
  }
}
