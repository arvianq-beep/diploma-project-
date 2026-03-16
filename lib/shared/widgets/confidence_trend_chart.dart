import 'package:diploma_application_ml/domain/models/incident_case.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

class ConfidenceTrendChart extends StatelessWidget {
  const ConfidenceTrendChart({super.key, required this.incidents});

  final List<IncidentCase> incidents;

  @override
  Widget build(BuildContext context) {
    final points = incidents.reversed.toList();

    return SizedBox(
      height: 220,
      child: LineChart(
        LineChartData(
          minY: 0,
          maxY: 1,
          borderData: FlBorderData(show: false),
          gridData: FlGridData(
            show: true,
            drawVerticalLine: false,
            getDrawingHorizontalLine: (value) =>
                FlLine(color: Colors.blueGrey.withValues(alpha: 0.12)),
          ),
          titlesData: FlTitlesData(
            topTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
            rightTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
            leftTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                reservedSize: 34,
                interval: 0.25,
                getTitlesWidget: (value, meta) => Text(
                  '${(value * 100).toInt()}%',
                  style: const TextStyle(fontSize: 11),
                ),
              ),
            ),
            bottomTitles: const AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
          ),
          lineBarsData: [
            LineChartBarData(
              spots: List.generate(
                points.length,
                (index) => FlSpot(
                  index.toDouble(),
                  points[index].analysis.rawConfidence,
                ),
              ),
              isCurved: true,
              color: Theme.of(context).colorScheme.primary,
              barWidth: 3,
              belowBarData: BarAreaData(
                show: true,
                color: Theme.of(
                  context,
                ).colorScheme.primary.withValues(alpha: 0.12),
              ),
              dotData: FlDotData(
                show: true,
                getDotPainter: (spot, percent, barData, index) {
                  return FlDotCirclePainter(
                    radius: 4,
                    color: Theme.of(context).colorScheme.primary,
                    strokeWidth: 0,
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}
