import 'dart:async';
import 'package:flutter/material.dart';
import '../services/api_service.dart';
import '../services/report_service.dart';
import '../models/threat_model.dart';
import '../components/threat_card.dart';
import '../components/confidence_chart.dart';
import '../components/attack_pie_chart.dart'; // <--- Импорт нового графика

class MainPage extends StatefulWidget {
  const MainPage({super.key});

  @override
  State<MainPage> createState() => _MainPageState();
}

class _MainPageState extends State<MainPage> {
  final List<ThreatLog> _logs = [];
  Timer? _timer;
  bool _isMonitoring = false;

  int _totalPackets = 0;
  int _threatsCount = 0;
  int _adversarialCount = 0;

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  void _toggleMonitoring() {
    setState(() {
      _isMonitoring = !_isMonitoring;
    });

    if (_isMonitoring) {
      _timer = Timer.periodic(const Duration(milliseconds: 1500), (
        timer,
      ) async {
        final newLog = await ApiService.fetchTrafficData();
        if (newLog != null) {
          if (mounted) {
            setState(() {
              _totalPackets++;
              _logs.insert(0, newLog);

              if (newLog.isThreat) {
                _threatsCount++;
                if (!newLog.isVerified) {
                  _adversarialCount++;
                  // ВАУ-ЭФФЕКТ: Показываем уведомление при обнаружении атаки на ИИ
                  _showSnack("⚠️ Adversarial Attack Detected!", Colors.orange);
                } else {
                  _showSnack(
                    "🛑 Threat Blocked: ${newLog.threatType}",
                    Colors.red,
                  );
                }
              }

              if (_logs.length > 50) _logs.removeLast();
            });
          }
        }
      });
    } else {
      _timer?.cancel();
    }
  }

  void _showSnack(String msg, Color color) {
    ScaffoldMessenger.of(context).clearSnackBars();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg, style: const TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: color,
        duration: const Duration(seconds: 1),
        behavior: SnackBarBehavior.floating,
        width: 400,
      ),
    );
  }

  Future<void> _exportReport() async {
    if (_logs.isEmpty) {
      _showSnack("No data to export", Colors.grey);
      return;
    }
    _showSnack("Generating PDF Report...", Colors.indigo);
    await ReportService.generateAndOpenReport(_logs);
  }

  @override
  Widget build(BuildContext context) {
    final threatOnlyLogs = _logs.where((l) => l.isThreat).toList();

    return Scaffold(
      backgroundColor: const Color(0xFFF1F5F9),
      appBar: AppBar(
        title: const Text("IITU CyberGuard: Secure Decision AI"),
        backgroundColor: const Color(0xFF0F172A),
        foregroundColor: Colors.white,
        actions: [
          // Индикатор статуса в шапке
          Container(
            margin: const EdgeInsets.only(right: 20),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: _isMonitoring ? Colors.green : Colors.red,
              borderRadius: BorderRadius.circular(20),
            ),
            child: Row(
              children: [
                const Icon(Icons.circle, size: 8, color: Colors.white),
                const SizedBox(width: 8),
                Text(
                  _isMonitoring ? "LIVE PROTECT" : "OFFLINE",
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      body: Row(
        children: [
          // САЙДБАР
          Container(
            width: 250,
            color: Colors.white,
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  "DASHBOARD",
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    color: Colors.grey,
                  ),
                ),
                const SizedBox(height: 20),
                _statCard("Scanned Packets", "$_totalPackets", Colors.blue),
                const SizedBox(height: 20),
                _statCard("Threats Found", "$_threatsCount", Colors.red),
                const SizedBox(height: 20),
                _statCard(
                  "Adversarial Attempts",
                  "$_adversarialCount",
                  Colors.orange,
                ),

                const Spacer(),
                const Divider(),

                ElevatedButton.icon(
                  onPressed: _exportReport,
                  icon: const Icon(Icons.picture_as_pdf),
                  label: const Text("EXPORT REPORT"),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.white,
                    foregroundColor: Colors.indigo,
                    elevation: 0,
                    side: const BorderSide(color: Colors.indigo),
                    minimumSize: const Size(double.infinity, 45),
                  ),
                ),
                const SizedBox(height: 10),
                ElevatedButton.icon(
                  onPressed: _toggleMonitoring,
                  icon: Icon(_isMonitoring ? Icons.pause : Icons.play_arrow),
                  label: Text(_isMonitoring ? "STOP SYSTEM" : "START SYSTEM"),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _isMonitoring
                        ? Colors.redAccent
                        : Colors.green,
                    foregroundColor: Colors.white,
                    minimumSize: const Size(double.infinity, 45),
                  ),
                ),
              ],
            ),
          ),

          // ОСНОВНОЙ КОНТЕНТ
          Expanded(
            child: Padding(
              padding: const EdgeInsets.all(20.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // СЕКЦИЯ ГРАФИКОВ (ВЕРХНЯЯ ЧАСТЬ)
                  SizedBox(
                    height: 220,
                    child: Row(
                      children: [
                        // График 1: Уверенность ИИ
                        Expanded(
                          flex: 2,
                          child: _DashboardCard(
                            title: "AI Confidence Stream",
                            child: ConfidenceChart(logs: _logs),
                          ),
                        ),
                        const SizedBox(width: 20),
                        // График 2: Распределение атак (НОВЫЙ)
                        Expanded(
                          flex: 1,
                          child: _DashboardCard(
                            title: "Attack Distribution",
                            child: AttackPieChart(logs: _logs),
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 20),

                  // СЕКЦИЯ СПИСКА (НИЖНЯЯ ЧАСТЬ)
                  const Text(
                    "Real-time Threat Feed",
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 10),

                  Expanded(
                    child: threatOnlyLogs.isEmpty
                        ? Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(
                                  Icons.security,
                                  size: 60,
                                  color: Colors.grey[300],
                                ),
                                const SizedBox(height: 10),
                                Text(
                                  _isMonitoring
                                      ? "Scanning network..."
                                      : "System is idle.",
                                  style: const TextStyle(color: Colors.grey),
                                ),
                              ],
                            ),
                          )
                        : ListView.builder(
                            itemCount: threatOnlyLogs.length,
                            itemBuilder: (ctx, index) =>
                                ThreatCard(log: threatOnlyLogs[index]),
                          ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _statCard(String label, String value, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          value,
          style: TextStyle(
            fontSize: 32,
            fontWeight: FontWeight.bold,
            color: color,
          ),
        ),
        Text(
          label,
          style: const TextStyle(color: Colors.black54, fontSize: 12),
        ),
      ],
    );
  }
}

// Обертка для карточек дашборда
class _DashboardCard extends StatelessWidget {
  final String title;
  final Widget child;

  const _DashboardCard({required this.title, required this.child});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        boxShadow: [
          BoxShadow(color: Colors.black.withOpacity(0.05), blurRadius: 10),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
          ),
          const SizedBox(height: 10),
          Expanded(child: child),
        ],
      ),
    );
  }
}
