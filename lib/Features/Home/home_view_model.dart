import 'package:diploma_application_ml/Serives/api_service.dart';
import 'package:flutter/foundation.dart';

import '../../Models/analysis_result.dart';

class HomeViewModel extends ChangeNotifier {
  final ApiService api;

  HomeViewModel({required this.api});

  int _index = 0;
  int get index => _index;

  bool _isLoading = false;
  bool get isLoading => _isLoading;

  String? _error;
  String? get error => _error;

  AnalysisResult? _lastResult;
  AnalysisResult? get lastResult => _lastResult;

  final List<AnalysisResult> _history = [];
  List<AnalysisResult> get history => List.unmodifiable(_history);

  /// ✅ Кол-во вкладок (Dashboard, Alerts, Reports, Datasets)
  static const int tabsCount = 4;

  void setIndex(int i) {
    // ✅ защита: индекс всегда 0..tabsCount-1
    if (i < 0) i = 0;
    if (i >= tabsCount) i = tabsCount - 1;

    _index = i;
    notifyListeners();
  }

  Future<void> runDemoAnalysis({bool goToAlerts = true}) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final demoFeatures = List<double>.generate(20, (i) => (i + 1) * 0.1);
      final result = await api.analyze(features: demoFeatures);

      _lastResult = result;
      _history.insert(0, result);

      // ✅ НЕ ломаем навигацию: переключаемся только если явно нужно
      if (goToAlerts) {
        setIndex(1); // Alerts
      }
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }
}
