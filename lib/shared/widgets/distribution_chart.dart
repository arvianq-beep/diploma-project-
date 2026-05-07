import 'dart:math';

import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

/// Returns a "nice" Y-axis interval so at most ~5 labels appear regardless
/// of how large maxVal is.
/// Examples: maxVal=8→1, maxVal=25→5, maxVal=160→50, maxVal=2500→500.
double _smartInterval(double maxVal) {
  if (maxVal <= 0) return 1;
  const maxTicks = 5;
  final raw = maxVal / maxTicks;
  final exp = (log(raw) / log(10)).floor();
  final pow10 = pow(10.0, exp).toDouble();
  final frac = raw / pow10;
  final niceFrac =
      frac < 1.5 ? 1.0 : frac < 3.5 ? 2.0 : frac < 7.5 ? 5.0 : 10.0;
  return (niceFrac * pow10).ceilToDouble();
}

class DistributionChart extends StatelessWidget {
  const DistributionChart({
    super.key,
    required this.values,
    required this.colors,
    required this.labels,
  });

  final List<double> values;
  final List<Color> colors;
  final List<String> labels;

  @override
  Widget build(BuildContext context) {
    final maxVal = values.fold(0.0, max);
    final interval = _smartInterval(maxVal);

    // Reserve enough width for the largest label (e.g. "2 000").
    final maxDigits = maxVal.toInt().toString().length;
    final reservedSize = (maxDigits * 8.0).clamp(28.0, 52.0);

    return Column(
      children: [
        SizedBox(
          height: 220,
          child: BarChart(
            BarChartData(
              borderData: FlBorderData(show: false),
              gridData: FlGridData(
                show: true,
                horizontalInterval: interval,
                drawVerticalLine: false,
                getDrawingHorizontalLine: (value) => FlLine(
                  color: Colors.blueGrey.withValues(alpha: 0.12),
                ),
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
                    reservedSize: reservedSize,
                    interval: interval,
                    getTitlesWidget: (value, meta) {
                      // Skip the max label if fl_chart adds one above the top bar.
                      if (value == meta.max) return const SizedBox.shrink();
                      return Text(
                        value.toInt().toString(),
                        style: const TextStyle(fontSize: 11),
                      );
                    },
                  ),
                ),
                bottomTitles: AxisTitles(
                  sideTitles: SideTitles(
                    showTitles: true,
                    getTitlesWidget: (value, meta) {
                      final index = value.toInt();
                      if (index < 0 || index >= labels.length) {
                        return const SizedBox.shrink();
                      }
                      return Padding(
                        padding: const EdgeInsets.only(top: 8),
                        child: Text(
                          labels[index],
                          style: const TextStyle(fontSize: 11),
                        ),
                      );
                    },
                  ),
                ),
              ),
              barGroups: List.generate(
                values.length,
                (index) => BarChartGroupData(
                  x: index,
                  barRods: [
                    BarChartRodData(
                      toY: values[index],
                      width: 32,
                      borderRadius: BorderRadius.circular(10),
                      color: colors[index],
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}
