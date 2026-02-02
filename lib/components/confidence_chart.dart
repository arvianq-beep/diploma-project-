import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import '../models/threat_model.dart';

class ConfidenceChart extends StatelessWidget {
  final List<ThreatLog> logs;

  const ConfidenceChart({super.key, required this.logs});

  @override
  Widget build(BuildContext context) {
    // Берем последние 20 пакетов для графика, чтобы он "бежал"
    final recentLogs = logs.take(20).toList().reversed.toList();

    // Если данных нет, показываем заглушку
    if (recentLogs.isEmpty) {
      return Center(
        child: Text(
          "Waiting for traffic...",
          style: TextStyle(color: Colors.grey[400]),
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: LineChart(
        LineChartData(
          gridData: FlGridData(
            show: true,
            drawVerticalLine: false,
            getDrawingHorizontalLine: (value) {
              return FlLine(
                color: Colors.grey.withOpacity(0.1),
                strokeWidth: 1,
              );
            },
          ),
          titlesData: FlTitlesData(
            leftTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                reservedSize: 40,
                getTitlesWidget: (value, meta) {
                  return Text(
                    "${value.toInt()}%",
                    style: const TextStyle(color: Colors.grey, fontSize: 10),
                  );
                },
              ),
            ),
            bottomTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
            topTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
            rightTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
          ),
          borderData: FlBorderData(show: false),
          minX: 0,
          maxX: (recentLogs.length - 1).toDouble(),
          minY: 0,
          maxY: 110, // Чуть больше 100, чтобы график не прилипал к верху
          lineBarsData: [
            LineChartBarData(
              spots: List.generate(recentLogs.length, (index) {
                // Y = Уверенность AI (0-100)
                return FlSpot(
                  index.toDouble(),
                  recentLogs[index].aiConfidence * 100,
                );
              }),
              isCurved: true,
              color: Colors.indigoAccent,
              barWidth: 3,
              isStrokeCapRound: true,
              dotData: FlDotData(show: true),
              belowBarData: BarAreaData(
                show: true,
                color: Colors.indigoAccent.withOpacity(0.2),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
