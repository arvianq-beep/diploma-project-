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

  void setIndex(int i) {
    _index = i;
    notifyListeners();
  }

  Future<void> runDemoAnalysis() async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final demoFeatures = List<double>.generate(20, (i) => (i + 1) * 0.1);
      final result = await api.analyze(features: demoFeatures);

      _lastResult = result;
      _history.insert(0, result);
      _index = 1; // после анализа → Alerts
    } catch (e) {
      _error = e.toString();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }
}
