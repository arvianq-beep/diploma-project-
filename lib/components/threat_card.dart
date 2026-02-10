import 'package:flutter/material.dart';
import '../models/threat_model.dart';

class ThreatCard extends StatelessWidget {
  final ThreatLog log;
  const ThreatCard({super.key, required this.log});

  @override
  Widget build(BuildContext context) {
    // Если это не угроза, не показываем ничего (или можно показывать зеленый лог)
    if (!log.isThreat) return const SizedBox.shrink();

    final bool isSecure = log.isVerified;
    // Красный для подтвержденных угроз, Оранжевый для атак на ИИ (Adversarial)
    final Color accentColor = isSecure
        ? const Color(0xFFFF3366)
        : Colors.orangeAccent;

    return Container(
      margin: const EdgeInsets.symmetric(vertical: 4, horizontal: 0),
      decoration: BoxDecoration(
        color: const Color(0xFF020617), // Темный фон
        border: Border(left: BorderSide(color: accentColor, width: 4)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.3),
            blurRadius: 4,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: InkWell(
        onTap: () => _showDetailsDialog(context),
        child: Padding(
          padding: const EdgeInsets.all(12.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Верхняя строка: Тип и Время
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(
                    child: Text(
                      log.threatType.toUpperCase(),
                      style: TextStyle(
                        color: accentColor,
                        fontFamily: 'monospace',
                        fontWeight: FontWeight.bold,
                        fontSize: 13,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Text(
                    log.timestamp,
                    style: const TextStyle(
                      color: Colors.blueGrey,
                      fontSize: 10,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),

              // Средняя строка: IP и Протокол
              Text(
                "SRC: ${log.sourceIp} | PROTO: ${log.protocol}",
                style: const TextStyle(
                  color: Colors.white70,
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 8),

              // Нижний блок: Уверенность ИИ
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                color: const Color(0xFF0F172A),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      "AI_CONF: ${(log.aiConfidence * 100).toStringAsFixed(1)}%",
                      style: const TextStyle(
                        color: Colors.cyanAccent,
                        fontSize: 10,
                        fontFamily: 'monospace',
                      ),
                    ),
                    Text(
                      isSecure ? "[ BLOCKED ]" : "[ ADVERSARIAL DETECTED ]",
                      style: TextStyle(
                        color: accentColor,
                        fontSize: 9,
                        fontWeight: FontWeight.bold,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showDetailsDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF020617),
        shape: const RoundedRectangleBorder(
          side: BorderSide(color: Color(0xFF1E293B)),
        ),
        title: const Text(
          "DEEP_PACKET_INSPECTION",
          style: TextStyle(
            color: Colors.white,
            fontFamily: 'monospace',
            fontSize: 14,
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _row("TIMESTAMP", log.timestamp),
            _row("SOURCE_IP", log.sourceIp),
            _row("PROTOCOL", log.protocol),
            const Divider(color: Colors.white12),
            _row("AI_SCORE", "${(log.aiConfidence * 100).toStringAsFixed(4)}%"),
            _row(
              "STATUS",
              log.isVerified ? "KNOWN_SIGNATURE" : "AI_PREDICTION",
            ),
            const SizedBox(height: 12),
            const Text(
              "PAYLOAD_HEX:",
              style: TextStyle(
                color: Colors.blueGrey,
                fontSize: 10,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 4),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              color: Colors.black,
              child: const Text(
                "0x45 0x00 0x05 0xdc 0x1a 0x2b 0x40 0x00\n0x40 0x06 0x3d 0xb2 0xc0 0xa8 0x01 0x05...",
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 10,
                  color: Colors.greenAccent,
                ),
              ),
            ),
            if (!log.isVerified) ...[
              const SizedBox(height: 10),
              Text(
                ">> WARNING: ${log.verificationDetails}",
                style: const TextStyle(
                  color: Colors.orangeAccent,
                  fontSize: 10,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text(
              "CLOSE",
              style: TextStyle(color: Colors.cyanAccent),
            ),
          ),
        ],
      ),
    );
  }

  Widget _row(String l, String v) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            l,
            style: const TextStyle(
              color: Colors.blueGrey,
              fontSize: 10,
              fontFamily: 'monospace',
            ),
          ),
          Text(
            v,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 10,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }
}
