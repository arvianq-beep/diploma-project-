import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/threat_model.dart';

class ApiService {
  // Адрес сервера Python
  static const String _baseUrl = 'http://127.0.0.1:5001/api/traffic';

  static Future<ThreatLog?> fetchTrafficData() async {
    try {
      final response = await http.get(Uri.parse(_baseUrl));

      if (response.statusCode == 200) {
        return ThreatLog.fromJson(json.decode(response.body));
      } else {
        print("Ошибка сервера: ${response.statusCode}");
        return null;
      }
    } catch (e) {
      print("Ошибка соединения: $e");
      return null;
    }
  }
}
