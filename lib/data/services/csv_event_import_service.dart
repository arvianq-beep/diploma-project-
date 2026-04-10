import 'dart:convert';
import 'dart:io';

import 'package:diploma_application_ml/domain/models/threat_event.dart';

typedef CsvParseProgressCallback =
    void Function({
      required int rowsParsed,
      required int? totalRowsEstimate,
      required String message,
    });

class CsvEventImportService {
  Future<List<ThreatEvent>> parseFile(
    String path, {
    int? limit,
    CsvParseProgressCallback? onProgress,
  }) async {
    final file = File(path);
    if (!await file.exists()) {
      return [];
    }

    onProgress?.call(
      rowsParsed: 0,
      totalRowsEstimate: null,
      message: 'Parsing CSV file...',
    );

    List<String>? headers;
    final events = <ThreatEvent>[];
    var rowIndex = 0;

    await for (final line in file
        .openRead()
        .transform(utf8.decoder)
        .transform(const LineSplitter())) {
      if (line.trim().isEmpty) {
        continue;
      }

      if (headers == null) {
        headers = _parseCsvLine(line);
        continue;
      }

      rowIndex++;
      final values = _parseCsvLine(line);
      final row = <String, String>{};
      for (var i = 0; i < headers.length; i++) {
        row[headers[i]] = i < values.length ? values[i] : '';
      }
      events.add(_eventFromRow(rowIndex, row, file.uri.pathSegments.last));

      if (rowIndex == 1 || rowIndex % 10 == 0) {
        onProgress?.call(
          rowsParsed: rowIndex,
          totalRowsEstimate: null,
          message: 'Parsing CSV rows: $rowIndex',
        );
      }

      if (limit != null && events.length >= limit) {
        break;
      }
    }

    onProgress?.call(
      rowsParsed: events.length,
      totalRowsEstimate: events.length,
      message: 'CSV parsing complete. ${events.length} events ready for analysis.',
    );

    return events;
  }

  ThreatEvent _eventFromRow(
    int index,
    Map<String, String> row,
    String fileName,
  ) {
    String normalizeProtocol(String value) {
      final normalized = value.trim();
      switch (normalized) {
        case '6':
          return 'TCP';
        case '17':
          return 'UDP';
        case '1':
          return 'ICMP';
        default:
          return normalized.isEmpty ? 'UNKNOWN' : normalized.toUpperCase();
      }
    }

    DateTime parseTimestamp(String raw) {
      if (raw.trim().isEmpty) {
        return DateTime.now();
      }
      return DateTime.tryParse(raw) ?? DateTime.now();
    }

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
      'Flow Bytes/s',
      'Flow Byts/s',
      'TotLen Fwd Pkts',
      'Total Length of Fwd Packets',
    ]);
    final backwardBytes = readDouble([
      'backward_bytes',
      'dbytes',
      'TotLen Bwd Pkts',
      'Total Length of Bwd Packets',
    ]);
    final flowBytesPerSecond = readDouble([
      'Flow Bytes/s',
      'Flow Byts/s',
      'bytes_per_second',
      'flow_bytes_per_second',
    ]);
    var totalBytes = readDouble([
      'bytes_transferred_kb',
      'bytes',
      'flow_bytes',
    ], 0);
    if (totalBytes == 0) {
      totalBytes = (forwardBytes + backwardBytes) / 1024;
    }
    if (totalBytes == 0 && flowBytesPerSecond > 0 && duration > 0) {
      totalBytes = (flowBytesPerSecond * duration) / 1024;
    }

    final forwardPackets = readDouble([
      'forward_packets',
      'spkts',
      'Tot Fwd Pkts',
      'Total Fwd Packets',
    ], 0);
    final backwardPackets = readDouble([
      'backward_packets',
      'dpkts',
      'Tot Bwd Pkts',
      'Total Backward Packets',
    ], 0);
    final totalPackets = forwardPackets + backwardPackets;
    var packetsPerSecond = readDouble([
      'packets_per_second',
      'Flow Packets/s',
      'Flow Pkts/s',
      'rate',
    ], 0);
    if (packetsPerSecond == 0 && duration > 0) {
      packetsPerSecond = totalPackets / duration;
    }

    final protocol = normalizeProtocol(
      read(['protocol', 'proto', 'Protocol'], 'UNKNOWN'),
    );
    final sourceIp = read([
      'source_ip',
      'srcip',
      'Src IP',
      'Source IP',
    ], '0.0.0.0');
    final destinationIp = read([
      'destination_ip',
      'dstip',
      'Dst IP',
      'Destination IP',
    ], '0.0.0.0');
    final sourcePort = readInt([
      'source_port',
      'sport',
      'Src Port',
      'Source Port',
    ]);
    final destinationPort = readInt([
      'destination_port',
      'dsport',
      'Destination Port',
      'Dst Port',
    ]);
    final label = read(['Label', 'label', 'attack_cat'], '');
    final repeatedAttempts = packetsPerSecond > 400 || destinationPort == 22;
    final offHoursActivity = false;
    final knownBadSource =
        sourceIp.startsWith('185.') || sourceIp.startsWith('45.');

    final anomalyScore = _deriveAnomalyScore(
      packetsPerSecond: packetsPerSecond,
      bytesTransferredKb: totalBytes,
      destinationPort: destinationPort,
    );
    final contextRisk = _deriveContextRisk(
      protocol: protocol,
      packetsPerSecond: packetsPerSecond,
      bytesTransferredKb: totalBytes,
    );

    return ThreatEvent(
      id: 'csv-$index',
      title: 'CSV Event $index',
      description: label.isEmpty
          ? 'Imported from $fileName'
          : 'Imported from $fileName with dataset label $label',
      sourceIp: sourceIp,
      destinationIp: destinationIp,
      sourcePort: sourcePort,
      destinationPort: destinationPort,
      protocol: protocol,
      bytesTransferredKb: totalBytes,
      durationSeconds: duration,
      packetsPerSecond: packetsPerSecond,
      failedLogins: readInt(['failed_logins']),
      anomalyScore: anomalyScore,
      contextRiskScore: contextRisk,
      knownBadSource:
          read(['known_bad_source'], 'false').toLowerCase() == 'true' ||
          knownBadSource,
      offHoursActivity:
          read(['off_hours_activity'], 'false').toLowerCase() == 'true' ||
          offHoursActivity,
      repeatedAttempts:
          read(['repeated_attempts'], 'false').toLowerCase() == 'true' ||
          repeatedAttempts,
      sampleSource: 'CSV Import',
      capturedAt: parseTimestamp(
        read(['Timestamp', 'timestamp', 'captured_at'], ''),
      ),
      tags: ['csv-import', if (label.isNotEmpty) 'dataset-label:$label'],
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
