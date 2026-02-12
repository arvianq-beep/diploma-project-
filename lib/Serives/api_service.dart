import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

import '../Models/analysis_result.dart';
import '../Models/reports_models.dart';

class ApiService {
  final String baseUrl;
  const ApiService({required this.baseUrl});

  Future<AnalysisResult> analyze({required List<double> features}) async {
    final uri = Uri.parse('$baseUrl/api/v1/analyze');

    final resp = await http.post(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'features': features}),
    );

    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw Exception('HTTP ${resp.statusCode}: ${resp.body}');
    }

    final data = jsonDecode(resp.body);
    if (data is! Map<String, dynamic>) {
      throw Exception('Invalid JSON format: expected object');
    }

    return AnalysisResult.fromJson(data);
  }

  Future<ReportsResponse> getReports({
    String? fromIsoUtc,
    String? toIsoUtc,
    int limit = 50,
    int offset = 0,
  }) async {
    final uri = Uri.parse('$baseUrl/api/v1/reports').replace(
      queryParameters: {
        if (fromIsoUtc != null) 'from': fromIsoUtc,
        if (toIsoUtc != null) 'to': toIsoUtc,
        'limit': '$limit',
        'offset': '$offset',
      },
    );

    final resp = await http.get(uri);

    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw Exception('HTTP ${resp.statusCode}: ${resp.body}');
    }

    final data = jsonDecode(resp.body);
    if (data is! Map<String, dynamic>) {
      throw Exception('Invalid JSON format: expected object');
    }

    return ReportsResponse.fromJson(data);
  }

  Future<Uint8List> exportReports({
    required String format, // "csv" or "json"
    String? fromIsoUtc,
    String? toIsoUtc,
  }) async {
    final uri = Uri.parse('$baseUrl/api/v1/reports/export').replace(
      queryParameters: {
        'format': format,
        if (fromIsoUtc != null) 'from': fromIsoUtc,
        if (toIsoUtc != null) 'to': toIsoUtc,
      },
    );

    final resp = await http.get(uri);

    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw Exception('HTTP ${resp.statusCode}: ${resp.body}');
    }

    return resp.bodyBytes;
  }
}
