import 'dart:convert';
import 'dart:io';

import 'package:diploma_application_ml/domain/models/threat_event.dart';

class CsvEventImportService {
  Future<List<ThreatEvent>> parseFile(String path) async {
    final file = File(path);
    final content = await file.readAsString();
    final rows = const LineSplitter()
        .convert(content)
        .where((line) => line.trim().isNotEmpty)
        .toList();
    if (rows.isEmpty) {
      return [];
    }

    final headers = _parseCsvLine(rows.first);
    final events = <ThreatEvent>[];
    for (var index = 1; index < rows.length; index++) {
      final values = _parseCsvLine(rows[index]);
      final row = <String, String>{};
      for (var i = 0; i < headers.length; i++) {
        row[headers[i]] = i < values.length ? values[i] : '';
      }
      events.add(_eventFromRow(index, row, file.uri.pathSegments.last));
    }
    return events;
  }

  ThreatEvent _eventFromRow(
    int index,
    Map<String, String> row,
    String fileName,
  ) {
    String read(List<String> keys, [String fallback = '']) {
      for (final key in keys) {
        for (final entry in row.entries) {
          if (entry.key.trim().toLowerCase() == key.trim().toLowerCase() &&
              entry.value.trim().isNotEmpty) {
            return entry.value.trim();
          }
        }
      }
      return fallback;
    }

    double readDouble(List<String> keys, [double fallback = 0]) {
      final raw = read(keys, '$fallback');
      final parsed = double.tryParse(raw.replaceAll(',', '.'));
      return parsed ?? fallback;
    }

    int readInt(List<String> keys, [int fallback = 0]) {
      return readDouble(keys, fallback.toDouble()).round();
    }

    var duration = readDouble([
      'duration_seconds',
      'duration',
      'dur',
      'Flow Duration',
    ], 1);
    if (duration > 10000) {
      duration = duration / 1000000;
    }

    final forwardBytes = readDouble([
      'forward_bytes',
      'sbytes',
      'TotLen Fwd Pkts',
      'Total Length of Fwd Packets',
    ]);
    final backwardBytes = readDouble([
      'backward_bytes',
      'dbytes',
      'TotLen Bwd Pkts',
      'Total Length of Bwd Packets',
    ]);
    var totalBytes = readDouble([
      'bytes_transferred_kb',
      'bytes',
      'flow_bytes',
    ], 0);
    if (totalBytes == 0) {
      totalBytes = (forwardBytes + backwardBytes) / 1024;
    }

    final totalPackets = readDouble([
      'total_packets',
      'spkts',
      'dpkts',
      'Tot Fwd Pkts',
    ], 0);
    var packetsPerSecond = readDouble([
      'packets_per_second',
      'Flow Packets/s',
      'rate',
    ], 0);
    if (packetsPerSecond == 0 && duration > 0) {
      packetsPerSecond = totalPackets / duration;
    }

    final anomalyScore = _deriveAnomalyScore(
      packetsPerSecond: packetsPerSecond,
      bytesTransferredKb: totalBytes,
      destinationPort: readInt([
        'destination_port',
        'dsport',
        'Destination Port',
      ]),
    );
    final contextRisk = _deriveContextRisk(
      protocol: read(['protocol', 'proto', 'Protocol'], 'UNKNOWN'),
      packetsPerSecond: packetsPerSecond,
      bytesTransferredKb: totalBytes,
    );

    return ThreatEvent(
      id: 'csv-$index',
      title: 'CSV Event $index',
      description: 'Imported from $fileName',
      sourceIp: read(['source_ip', 'srcip', 'Src IP'], '0.0.0.0'),
      destinationIp: read(['destination_ip', 'dstip', 'Dst IP'], '0.0.0.0'),
      sourcePort: readInt(['source_port', 'sport', 'Src Port']),
      destinationPort: readInt([
        'destination_port',
        'dsport',
        'Destination Port',
      ]),
      protocol: read(['protocol', 'proto', 'Protocol'], 'UNKNOWN'),
      bytesTransferredKb: totalBytes,
      durationSeconds: duration,
      packetsPerSecond: packetsPerSecond,
      failedLogins: readInt(['failed_logins']),
      anomalyScore: anomalyScore,
      contextRiskScore: contextRisk,
      knownBadSource:
          read(['known_bad_source'], 'false').toLowerCase() == 'true',
      offHoursActivity:
          read(['off_hours_activity'], 'false').toLowerCase() == 'true',
      repeatedAttempts:
          read(['repeated_attempts'], 'false').toLowerCase() == 'true',
      sampleSource: 'CSV Import',
      capturedAt: DateTime.now(),
      tags: const ['csv-import'],
    );
  }

  List<String> _parseCsvLine(String line) {
    final values = <String>[];
    final buffer = StringBuffer();
    var insideQuotes = false;

    for (var i = 0; i < line.length; i++) {
      final char = line[i];
      if (char == '"') {
        if (insideQuotes && i + 1 < line.length && line[i + 1] == '"') {
          buffer.write('"');
          i++;
        } else {
          insideQuotes = !insideQuotes;
        }
      } else if (char == ',' && !insideQuotes) {
        values.add(buffer.toString().trim());
        buffer.clear();
      } else {
        buffer.write(char);
      }
    }
    values.add(buffer.toString().trim());
    return values;
  }

  double _deriveAnomalyScore({
    required double packetsPerSecond,
    required double bytesTransferredKb,
    required int destinationPort,
  }) {
    var score = 0.18;
    if (packetsPerSecond > 500) score += 0.24;
    if (bytesTransferredKb > 10000) score += 0.20;
    if ({22, 23, 3389}.contains(destinationPort)) score += 0.14;
    return score.clamp(0.1, 0.95);
  }

  double _deriveContextRisk({
    required String protocol,
    required double packetsPerSecond,
    required double bytesTransferredKb,
  }) {
    var score = 0.16;
    if (protocol.toUpperCase() == 'ICMP') score += 0.18;
    if (packetsPerSecond > 500) score += 0.16;
    if (bytesTransferredKb > 10000) score += 0.18;
    return score.clamp(0.1, 0.9);
  }
}
