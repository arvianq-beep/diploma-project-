import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import '../models/threat_model.dart';

class AttackPieChart extends StatelessWidget {
  final List<ThreatLog> logs;

  const AttackPieChart({super.key, required this.logs});

  @override
  Widget build(BuildContext context) {
    // 1. Считаем статистику по типам атак
    Map<String, int> attackCounts = {};
    int totalThreats = 0;

    for (var log in logs) {
      if (log.isThreat) {
        attackCounts[log.threatType] = (attackCounts[log.threatType] ?? 0) + 1;
        totalThreats++;
      }
    }

    if (totalThreats == 0) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.pie_chart_outline, color: Colors.grey[300], size: 40),
            const SizedBox(height: 8),
            Text(
              "No threats data",
              style: TextStyle(color: Colors.grey[400], fontSize: 12),
            ),
          ],
        ),
      );
    }

    // 2. Генерируем секции для графика
    final List<Color> palette = [
      Colors.redAccent,
      Colors.orangeAccent,
      Colors.blueAccent,
      Colors.purpleAccent,
      Colors.teal,
    ];

    int colorIndex = 0;
    List<PieChartSectionData> sections = [];

    attackCounts.forEach((key, value) {
      final isLarge = value / totalThreats > 0.3; // Выделяем крупные секции
      sections.add(
        PieChartSectionData(
          color: palette[colorIndex % palette.length],
          value: value.toDouble(),
          title: '${(value / totalThreats * 100).toStringAsFixed(0)}%',
          radius: isLarge ? 50 : 40,
          titleStyle: const TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.bold,
            color: Colors.white,
          ),
          badgeWidget: _Badge(
            key,
            size: 30,
            borderColor: palette[colorIndex % palette.length],
          ),
          badgePositionPercentageOffset: 1.4,
        ),
      );
      colorIndex++;
    });

    return PieChart(
      PieChartData(
        sections: sections,
        centerSpaceRadius: 30,
        sectionsSpace: 2,
        borderData: FlBorderData(show: false),
      ),
    );
  }
}

// Виджет для подписей (DDoS, SQL...)
class _Badge extends StatelessWidget {
  final String text;
  final double size;
  final Color borderColor;

  const _Badge(this.text, {required this.size, required this.borderColor});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: borderColor),
        boxShadow: [
          BoxShadow(color: Colors.black.withOpacity(0.1), blurRadius: 2),
        ],
      ),
      child: Text(
        text,
        style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold),
      ),
    );
  }
}
