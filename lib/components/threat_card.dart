import 'package:flutter/material.dart';
import '../models/threat_model.dart';

class ThreatCard extends StatelessWidget {
  final ThreatLog log;

  const ThreatCard({super.key, required this.log});

  @override
  Widget build(BuildContext context) {
    if (!log.isThreat) return const SizedBox.shrink();

    final bool isSecure = log.isVerified;
    final Color borderColor = isSecure ? Colors.red : Colors.orange;
    final IconData statusIcon = isSecure ? Icons.gpp_bad : Icons.warning_amber;

    return Card(
      elevation: 2,
      margin: const EdgeInsets.symmetric(vertical: 6, horizontal: 0),
      color: Colors.white,
      shape: RoundedRectangleBorder(
        side: BorderSide(color: borderColor, width: 2),
        borderRadius: BorderRadius.circular(10),
      ),
      // Делаем карточку кликабельной через InkWell
      child: InkWell(
        borderRadius: BorderRadius.circular(10),
        onTap: () => _showDetailsDialog(context), // При клике открываем диалог
        child: Padding(
          padding: const EdgeInsets.all(12.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Заголовок
              Row(
                children: [
                  Icon(statusIcon, color: borderColor),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      log.threatType,
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Text(
                    log.timestamp,
                    style: const TextStyle(color: Colors.grey),
                  ),
                  const SizedBox(width: 8),
                  const Icon(Icons.info_outline, size: 16, color: Colors.grey),
                ],
              ),
              const SizedBox(height: 8),

              Text("Source IP: ${log.sourceIp} | Protocol: ${log.protocol}"),
              const SizedBox(height: 8),

              // Блок уверенности
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.grey[100],
                  borderRadius: BorderRadius.circular(5),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      "AI Confidence: ${(log.aiConfidence * 100).toStringAsFixed(1)}%",
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 6,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: isSecure ? Colors.red[50] : Colors.orange[50],
                        border: Border.all(color: borderColor),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        isSecure ? "VERIFIED THREAT" : "ADVERSARIAL SUSPICION",
                        style: TextStyle(
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                          color: borderColor,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

              if (!isSecure) ...[
                const SizedBox(height: 5),
                Text(
                  "Warning: ${log.verificationDetails}",
                  style: const TextStyle(
                    fontSize: 11,
                    color: Colors.orange,
                    fontStyle: FontStyle.italic,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  // Всплывающее окно с "техническими деталями" (Deep Packet Inspection)
  void _showDetailsDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Row(
          children: [
            const Icon(Icons.analytics, color: Colors.indigo),
            const SizedBox(width: 10),
            const Text("Deep Packet Inspection"),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _detailRow("Timestamp:", log.timestamp),
            _detailRow("Source IP:", log.sourceIp),
            _detailRow("Destination IP:", "192.168.1.5 (Server)"),
            _detailRow("Protocol:", log.protocol),
            const Divider(),
            _detailRow("Threat Class:", log.threatType),
            _detailRow(
              "AI Confidence:",
              "${(log.aiConfidence * 100).toStringAsFixed(4)}%",
            ),
            _detailRow(
              "Verification:",
              log.isVerified ? "Passed" : "Failed (Adversarial)",
            ),
            const SizedBox(height: 10),
            const Text(
              "Raw Payload Header:",
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              color: Colors.black12,
              child: Text(
                "0x45 0x00 0x05 0xdc 0x1a 0x2b 0x40 0x00\n0x40 0x${log.protocol == 'TCP' ? '06' : '11'} 0x3d 0xb2 ...",
                style: const TextStyle(fontFamily: 'Courier', fontSize: 12),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text("CLOSE REPORT"),
          ),
        ],
      ),
    );
  }

  Widget _detailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: const TextStyle(
              fontWeight: FontWeight.w500,
              color: Colors.grey,
            ),
          ),
          Text(value, style: const TextStyle(fontWeight: FontWeight.bold)),
        ],
      ),
    );
  }
}
