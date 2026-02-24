import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

import '../Models/analysis_result.dart';
import '../Models/reports_models.dart';

class ApiService {
  final String baseUrl;
  const ApiService({required this.baseUrl});

  // ---------- Single event analyze ----------
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

  // ---------- Reports ----------
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

  // ---------- Datasets ----------
  Future<List<Map<String, dynamic>>> listDatasets() async {
    final uri = Uri.parse('$baseUrl/api/v1/datasets');
    final resp = await http.get(uri);

    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw Exception('HTTP ${resp.statusCode}: ${resp.body}');
    }

    final data = jsonDecode(resp.body);
    if (data is! List) {
      throw Exception('Invalid JSON format: expected array');
    }

    return data.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Future<Map<String, dynamic>> uploadDatasetFile({
    required String filePath,
  }) async {
    final file = File(filePath);
    if (!await file.exists()) {
      throw Exception('File not found: $filePath');
    }

    final uri = Uri.parse('$baseUrl/api/v1/datasets/upload');
    final req = http.MultipartRequest('POST', uri);

    req.files.add(await http.MultipartFile.fromPath('file', file.path));

    final streamed = await req.send();
    final body = await streamed.stream.bytesToString();

    if (streamed.statusCode < 200 || streamed.statusCode >= 300) {
      throw Exception('HTTP ${streamed.statusCode}: $body');
    }

    final data = jsonDecode(body);
    if (data is! Map<String, dynamic>) {
      throw Exception('Invalid JSON format: expected object');
    }

    return data;
  }

  /// Runs analysis on a stored dataset by datasetId.
  /// Backend: POST /api/v1/datasets/<dataset_id>/analyze?limit=50
  Future<Map<String, dynamic>> analyzeDataset({
    required String datasetId,
    int limit = 50,
  }) async {
    final uri = Uri.parse(
      '$baseUrl/api/v1/datasets/$datasetId/analyze',
    ).replace(queryParameters: {'limit': '$limit'});

    final resp = await http.post(uri);

    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw Exception('HTTP ${resp.statusCode}: ${resp.body}');
    }

    final data = jsonDecode(resp.body);
    if (data is! Map<String, dynamic>) {
      throw Exception('Invalid JSON format: expected object');
    }

    return data;
  }
}
