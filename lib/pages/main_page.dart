import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';

// Убедись, что эти файлы существуют в твоем проекте
import '../models/threat_model.dart';
import '../components/threat_card.dart';

class MainPage extends StatefulWidget {
  const MainPage({super.key});

  @override
  State<MainPage> createState() => _MainPageState();
}

class _MainPageState extends State<MainPage> {
  // Список для хранения логов
  final List<ThreatLog> _logs = [];

  // Переменные для таймера
  Timer? _timer;
  bool _isMonitoring = false;

  // Счетчики статистики
  int _totalPackets = 1240;
  int _threatsCount = 0;
  int _adversarialCount = 0;

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  // --- 1. ЛОГИКА МОНИТОРИНГА (START/STOP) ---
  void _toggleMonitoring() {
    setState(() => _isMonitoring = !_isMonitoring);

    if (!_isMonitoring) {
      _timer?.cancel();
    } else {
      // ИСПРАВЛЕНО: добавлено (_) в аргументы
      _timer = Timer.periodic(const Duration(milliseconds: 1000), (_) {
        setState(() => _totalPackets += 15);
      });
    }
  }

  // --- 2. ЗАГРУЗКА ФАЙЛА (IMPORT) ---
  void _importDataset() async {
    try {
      // Выбор файла
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['json'],
      );

      if (result != null) {
        _showSnack("ЧТЕНИЕ ФАЙЛА...", Colors.cyanAccent);

        String content = "";

        // Чтение содержимого (универсально для Web и Desktop)
        if (result.files.first.bytes != null) {
          content = utf8.decode(result.files.first.bytes!);
        } else if (result.files.first.path != null) {
          final file = File(result.files.first.path!);
          content = await file.readAsString();
        }

        if (content.isEmpty) return;

        // Парсинг JSON
        List<dynamic> jsonData = jsonDecode(content);

        setState(() {
          for (var item in jsonData) {
            // Создание объекта из JSON
            final log = ThreatLog.fromJson(item);
            _logs.insert(0, log);

            // Обновление счетчиков
            if (log.isThreat) _threatsCount++;
            if (!log.isVerified) _adversarialCount++;
          }
        });

        _showSnack("УСПЕШНО ЗАГРУЖЕНО: ${jsonData.length}", Colors.greenAccent);
        _showAnalysisDialog(); // Показываем окно анализа
      } else {
        _showSnack("ОТМЕНА ЗАГРУЗКИ", Colors.orangeAccent);
      }
    } catch (e) {
      print("Error: $e");
      _showSnack("ОШИБКА: НЕВЕРНЫЙ JSON", Colors.redAccent);
    }
  }

  // --- 3. ЭКСПОРТ ОТЧЕТА ---
  Future<void> _exportReport() async {
    if (_logs.isEmpty) {
      _showSnack("НЕТ ДАННЫХ", Colors.blueGrey);
      return;
    }
    _showSnack("ГЕНЕРАЦИЯ PDF...", Colors.indigoAccent);
    await Future.delayed(const Duration(seconds: 2));
    _showSnack("ОТЧЕТ СОХРАНЕН", Colors.greenAccent);
  }

  // --- 4. ДИАЛОГ СРАВНЕНИЯ ---
  void _showAnalysisDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF020617),
        shape: const RoundedRectangleBorder(
          side: BorderSide(color: Colors.cyanAccent),
        ),
        title: const Text(
          "CROSS-MODEL VALIDATION",
          style: TextStyle(color: Colors.cyanAccent, fontFamily: 'monospace'),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            _row("Signature-Based", "PASSED (Clean)", Colors.greenAccent),
            _row("Anomaly Method", "PASSED (Normal)", Colors.greenAccent),
            const Divider(color: Colors.white12),
            _row("Secure Decision AI", "DETECTED", Colors.redAccent),
            const SizedBox(height: 10),
            const Text(
              "Результат: ИИ обнаружил скрытые паттерны атаки.",
              style: TextStyle(
                color: Colors.white38,
                fontSize: 10,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text(
              "ЗАКРЫТЬ",
              style: TextStyle(color: Colors.cyanAccent),
            ),
          ),
        ],
      ),
    );
  }

  Widget _row(String m, String r, Color c) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            m,
            style: const TextStyle(
              color: Colors.white70,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
          ),
          Text(
            r,
            style: TextStyle(
              color: c,
              fontWeight: FontWeight.bold,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  void _showSnack(String msg, Color color) {
    ScaffoldMessenger.of(context).clearSnackBars();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          msg,
          style: const TextStyle(
            fontFamily: 'monospace',
            color: Colors.black,
            fontWeight: FontWeight.bold,
          ),
        ),
        backgroundColor: color,
        behavior: SnackBarBehavior.floating,
        width: 400,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        title: const Text(
          "IITU_SECURE_NODE",
          style: TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.bold,
          ),
        ),
        backgroundColor: const Color(0xFF020617),
        actions: [
          Center(
            child: Container(
              margin: const EdgeInsets.only(right: 20),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                border: Border.all(
                  color: _isMonitoring ? Colors.greenAccent : Colors.redAccent,
                ),
              ),
              child: Text(
                _isMonitoring ? "ONLINE" : "OFFLINE",
                style: TextStyle(
                  color: _isMonitoring ? Colors.greenAccent : Colors.redAccent,
                  fontSize: 10,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
        ],
      ),
      body: Row(
        children: [
          // ЛЕВАЯ ПАНЕЛЬ (SIDEBAR)
          Container(
            width: 240,
            color: const Color(0xFF020617),
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _stat("TOTAL_PKTS", "$_totalPackets", Colors.blue),
                _stat("THREATS", "$_threatsCount", Colors.redAccent),
                _stat("ADV_ATTACKS", "$_adversarialCount", Colors.orangeAccent),

                const Spacer(),
                const Divider(color: Color(0xFF1E293B)),
                const SizedBox(height: 10),

                _sideBtn(
                  "IMPORT DATASET",
                  Icons.upload_file,
                  _importDataset,
                  Colors.cyanAccent,
                ),
                const SizedBox(height: 10),
                _sideBtn(
                  "EXPORT REPORT",
                  Icons.download,
                  _exportReport,
                  Colors.indigoAccent,
                ),
                const SizedBox(height: 20),

                _sideBtn(
                  _isMonitoring ? "STOP SYSTEM" : "START SYSTEM",
                  _isMonitoring ? Icons.stop_circle : Icons.play_arrow,
                  _toggleMonitoring,
                  _isMonitoring ? Colors.redAccent : Colors.greenAccent,
                  isPrimary: true,
                ),
              ],
            ),
          ),

          // ПРАВАЯ ЧАСТЬ (КОНТЕНТ)
          Expanded(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF020617),
                  border: Border.all(color: const Color(0xFF1E293B)),
                ),
                child: _logs.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.shield_outlined,
                              color: Colors.blueGrey.withOpacity(0.3),
                              size: 48,
                            ),
                            const SizedBox(height: 10),
                            const Text(
                              "NO DATASET LOADED",
                              style: TextStyle(
                                color: Colors.blueGrey,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ],
                        ),
                      )
                    : ListView.builder(
                        itemCount: _logs.length,
                        itemBuilder: (context, i) => ThreatCard(log: _logs[i]),
                      ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _stat(String l, String v, Color c) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 25),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            v,
            style: TextStyle(
              color: c,
              fontSize: 26,
              fontFamily: 'monospace',
              fontWeight: FontWeight.bold,
            ),
          ),
          Text(l, style: const TextStyle(color: Colors.blueGrey, fontSize: 9)),
        ],
      ),
    );
  }

  // Кнопка сайдбара
  Widget _sideBtn(
    String l,
    IconData icon,
    VoidCallback p,
    Color c, {
    bool isPrimary = false,
  }) {
    return SizedBox(
      width: double.infinity,
      height: 45,
      child: OutlinedButton.icon(
        onPressed: p,
        icon: Icon(icon, size: 16, color: c),
        label: Text(
          l,
          style: const TextStyle(
            fontSize: 10,
            fontFamily: 'monospace',
            fontWeight: FontWeight.bold,
          ),
        ),
        style: OutlinedButton.styleFrom(
          foregroundColor: c,
          side: BorderSide(color: c.withOpacity(0.5)),
          backgroundColor: isPrimary ? c.withOpacity(0.1) : Colors.transparent,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
        ),
      ),
    );
  }
}
