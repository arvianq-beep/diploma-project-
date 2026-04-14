import 'dart:convert';
import 'dart:io';

import 'package:diploma_application_ml/domain/models/threat_event.dart';

/// CIC-IDS2017 column name aliases for each of the 77 canonical features.
/// Must stay in sync with backend/ml/schema.py CIC_COLUMN_ALIASES.
const Map<String, List<String>> _cicAliases = {
  'ack_flag_count': ['ACK Flag Count', 'ack_flag_count'],
  'act_data_pkt_fwd': ['act_data_pkt_fwd'],
  'active_max': ['Active Max', 'active_max'],
  'active_mean': ['Active Mean', 'active_mean'],
  'active_min': ['Active Min', 'active_min'],
  'active_std': ['Active Std', 'active_std'],
  'avg_bwd_segment_size': ['Avg Bwd Segment Size', 'avg_bwd_segment_size'],
  'avg_fwd_segment_size': ['Avg Fwd Segment Size', 'avg_fwd_segment_size'],
  'avg_packet_size': ['Average Packet Size', 'Avg Pkt Size', 'avg_packet_size'],
  'bwd_avg_bulk_rate': ['Bwd Avg Bulk Rate', 'bwd_avg_bulk_rate'],
  'bwd_avg_bytes_bulk': ['Bwd Avg Bytes/Bulk', 'bwd_avg_bytes_bulk'],
  'bwd_avg_packets_bulk': ['Bwd Avg Packets/Bulk', 'bwd_avg_packets_bulk'],
  'bwd_header_length': ['Bwd Header Length', 'bwd_header_length'],
  'bwd_iat_max': ['Bwd IAT Max', 'bwd_iat_max'],
  'bwd_iat_mean': ['Bwd IAT Mean', 'bwd_iat_mean'],
  'bwd_iat_min': ['Bwd IAT Min', 'bwd_iat_min'],
  'bwd_iat_std': ['Bwd IAT Std', 'bwd_iat_std'],
  'bwd_iat_total': ['Bwd IAT Total', 'bwd_iat_total'],
  'bwd_packet_length_max': ['Bwd Packet Length Max', 'bwd_packet_length_max'],
  'bwd_packet_length_mean': ['Bwd Packet Length Mean', 'bwd_packet_length_mean'],
  'bwd_packet_length_min': ['Bwd Packet Length Min', 'bwd_packet_length_min'],
  'bwd_packet_length_std': ['Bwd Packet Length Std', 'bwd_packet_length_std'],
  'bwd_packets_per_s': ['Bwd Packets/s', 'Bwd Pkts/s', 'bwd_packets_per_s'],
  'bwd_psh_flags': ['Bwd PSH Flags', 'bwd_psh_flags'],
  'bwd_urg_flags': ['Bwd URG Flags', 'bwd_urg_flags'],
  'cwr_flag_count': ['CWE Flag Count', 'CWR Flag Count', 'cwr_flag_count'],
  'destination_port': ['Destination Port', 'Dst Port', 'dst_port', 'destination_port'],
  'down_up_ratio': ['Down/Up Ratio', 'down_up_ratio'],
  'ece_flag_count': ['ECE Flag Count', 'ece_flag_count'],
  'fin_flag_count': ['FIN Flag Count', 'fin_flag_count'],
  'flow_bytes_per_s': ['Flow Bytes/s', 'Flow Byts/s', 'flow_bytes_per_s', 'bytes_per_second'],
  'flow_duration': ['Flow Duration', 'flow_duration', 'duration', 'dur'],
  'flow_iat_max': ['Flow IAT Max', 'flow_iat_max'],
  'flow_iat_mean': ['Flow IAT Mean', 'flow_iat_mean'],
  'flow_iat_min': ['Flow IAT Min', 'flow_iat_min'],
  'flow_iat_std': ['Flow IAT Std', 'flow_iat_std'],
  'flow_packets_per_s': ['Flow Packets/s', 'Flow Pkts/s', 'flow_packets_per_s', 'packets_per_second', 'rate'],
  'fwd_avg_bulk_rate': ['Fwd Avg Bulk Rate', 'fwd_avg_bulk_rate'],
  'fwd_avg_bytes_bulk': ['Fwd Avg Bytes/Bulk', 'fwd_avg_bytes_bulk'],
  'fwd_avg_packets_bulk': ['Fwd Avg Packets/Bulk', 'fwd_avg_packets_bulk'],
  'fwd_header_length': ['Fwd Header Length', 'Fwd Header Length.1', 'fwd_header_length'],
  'fwd_iat_max': ['Fwd IAT Max', 'fwd_iat_max'],
  'fwd_iat_mean': ['Fwd IAT Mean', 'fwd_iat_mean'],
  'fwd_iat_min': ['Fwd IAT Min', 'fwd_iat_min'],
  'fwd_iat_std': ['Fwd IAT Std', 'fwd_iat_std'],
  'fwd_iat_total': ['Fwd IAT Total', 'fwd_iat_total'],
  'fwd_packet_length_max': ['Fwd Packet Length Max', 'fwd_packet_length_max'],
  'fwd_packet_length_mean': ['Fwd Packet Length Mean', 'fwd_packet_length_mean'],
  'fwd_packet_length_min': ['Fwd Packet Length Min', 'fwd_packet_length_min'],
  'fwd_packet_length_std': ['Fwd Packet Length Std', 'fwd_packet_length_std'],
  'fwd_packets_per_s': ['Fwd Packets/s', 'Fwd Pkts/s', 'fwd_packets_per_s'],
  'fwd_psh_flags': ['Fwd PSH Flags', 'fwd_psh_flags'],
  'fwd_urg_flags': ['Fwd URG Flags', 'fwd_urg_flags'],
  'idle_max': ['Idle Max', 'idle_max'],
  'idle_mean': ['Idle Mean', 'idle_mean'],
  'idle_min': ['Idle Min', 'idle_min'],
  'idle_std': ['Idle Std', 'idle_std'],
  'init_win_bytes_backward': ['Init_Win_bytes_backward', 'init_win_bytes_backward'],
  'init_win_bytes_forward': ['Init_Win_bytes_forward', 'init_win_bytes_forward'],
  'min_seg_size_forward': ['min_seg_size_forward'],
  'packet_length_max': ['Max Packet Length', 'Packet Length Max', 'packet_length_max'],
  'packet_length_mean': ['Packet Length Mean', 'packet_length_mean'],
  'packet_length_min': ['Min Packet Length', 'Packet Length Min', 'packet_length_min'],
  'packet_length_std': ['Packet Length Std', 'packet_length_std'],
  'packet_length_variance': ['Packet Length Variance', 'packet_length_variance'],
  'psh_flag_count': ['PSH Flag Count', 'psh_flag_count'],
  'rst_flag_count': ['RST Flag Count', 'rst_flag_count'],
  'subflow_bwd_bytes': ['Subflow Bwd Bytes', 'subflow_bwd_bytes'],
  'subflow_bwd_packets': ['Subflow Bwd Packets', 'subflow_bwd_packets'],
  'subflow_fwd_bytes': ['Subflow Fwd Bytes', 'subflow_fwd_bytes'],
  'subflow_fwd_packets': ['Subflow Fwd Packets', 'subflow_fwd_packets'],
  'syn_flag_count': ['SYN Flag Count', 'syn_flag_count'],
  'total_bwd_packets': ['Total Backward Packets', 'Tot Bwd Pkts', 'total_bwd_packets', 'dpkts'],
  'total_fwd_packets': ['Total Fwd Packets', 'Tot Fwd Pkts', 'total_fwd_packets', 'spkts'],
  'total_length_bwd_packets': ['Total Length of Bwd Packets', 'TotLen Bwd Pkts', 'total_length_bwd_packets', 'dbytes'],
  'total_length_fwd_packets': ['Total Length of Fwd Packets', 'TotLen Fwd Pkts', 'total_length_fwd_packets', 'sbytes'],
  'urg_flag_count': ['URG Flag Count', 'urg_flag_count'],
};

class CsvEventImportService {
  Future<List<ThreatEvent>> parseFile(String path) async {
    final file = File(path);
    final content = await file.readAsString();
    final rows = const LineSplitter()
        .convert(content)
        .where((line) => line.trim().isNotEmpty)
        .toList();
    if (rows.isEmpty) return [];

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
      if (raw.trim().isEmpty) return DateTime.now();
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
      return double.tryParse(raw.replaceAll(',', '.')) ?? fallback;
    }

    int readInt(List<String> keys, [int fallback = 0]) =>
        readDouble(keys, fallback.toDouble()).round();

    // --- Extract all 77 canonical features from the row (primary ML path) ---
    final flowFeatures = _extractFlowFeatures(row);

    // CIC stores flow_duration in microseconds; convert to seconds here so
    // the value matches what the backend expects at inference time.
    if (flowFeatures.containsKey('flow_duration')) {
      final raw = flowFeatures['flow_duration']!;
      if (raw > 10000) {
        flowFeatures['flow_duration'] = raw / 1000000.0;
      }
    }

    // --- Legacy fields (metadata + compat fallback) ---
    final protocol = normalizeProtocol(
      read(['protocol', 'proto', 'Protocol'], 'UNKNOWN'),
    );
    final sourceIp = read(['source_ip', 'srcip', 'Src IP', 'Source IP'], '0.0.0.0');
    final destinationIp = read(['destination_ip', 'dstip', 'Dst IP', 'Destination IP'], '0.0.0.0');
    final sourcePort = readInt(['source_port', 'sport', 'Src Port', 'Source Port']);
    final destinationPort =
        flowFeatures['destination_port']?.round() ??
        readInt(['destination_port', 'dsport', 'Destination Port', 'Dst Port']);
    final label = read(['Label', 'label', 'attack_cat'], '');

    var duration = flowFeatures['flow_duration'] ??
        readDouble(['duration_seconds', 'duration', 'dur', 'Flow Duration'], 1);
    if (duration > 10000) duration = duration / 1000000;

    var packetsPerSecond = flowFeatures['flow_packets_per_s'] ??
        readDouble(['packets_per_second', 'Flow Packets/s', 'Flow Pkts/s', 'rate'], 0);

    final fwdPkts = flowFeatures['total_fwd_packets'] ??
        readDouble(['forward_packets', 'spkts', 'Tot Fwd Pkts', 'Total Fwd Packets'], 0);
    final bwdPkts = flowFeatures['total_bwd_packets'] ??
        readDouble(['backward_packets', 'dpkts', 'Tot Bwd Pkts', 'Total Backward Packets'], 0);
    if (packetsPerSecond == 0 && duration > 0) {
      packetsPerSecond = (fwdPkts + bwdPkts) / duration;
    }

    final fwdBytes = flowFeatures['total_length_fwd_packets'] ??
        readDouble(['forward_bytes', 'sbytes', 'TotLen Fwd Pkts', 'Total Length of Fwd Packets'], 0);
    final bwdBytes = flowFeatures['total_length_bwd_packets'] ??
        readDouble(['backward_bytes', 'dbytes', 'TotLen Bwd Pkts', 'Total Length of Bwd Packets'], 0);
    var bytesKb = readDouble(['bytes_transferred_kb', 'bytes', 'flow_bytes'], 0);
    if (bytesKb == 0) bytesKb = (fwdBytes + bwdBytes) / 1024;
    if (bytesKb == 0 && (flowFeatures['flow_bytes_per_s'] ?? 0) > 0 && duration > 0) {
      bytesKb = (flowFeatures['flow_bytes_per_s']! * duration) / 1024;
    }

    final repeatedAttempts = packetsPerSecond > 400 || destinationPort == 22;
    final knownBadSource =
        sourceIp.startsWith('185.') || sourceIp.startsWith('45.');

    final anomalyScore = _deriveAnomalyScore(
      packetsPerSecond: packetsPerSecond,
      bytesTransferredKb: bytesKb,
      destinationPort: destinationPort,
    );
    final contextRisk = _deriveContextRisk(
      protocol: protocol,
      packetsPerSecond: packetsPerSecond,
      bytesTransferredKb: bytesKb,
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
      bytesTransferredKb: bytesKb,
      durationSeconds: duration,
      packetsPerSecond: packetsPerSecond,
      failedLogins: readInt(['failed_logins']),
      anomalyScore: anomalyScore,
      contextRiskScore: contextRisk,
      knownBadSource:
          read(['known_bad_source'], 'false').toLowerCase() == 'true' ||
          knownBadSource,
      offHoursActivity:
          read(['off_hours_activity'], 'false').toLowerCase() == 'true',
      repeatedAttempts:
          read(['repeated_attempts'], 'false').toLowerCase() == 'true' ||
          repeatedAttempts,
      sampleSource: 'CSV Import',
      capturedAt: parseTimestamp(
        read(['Timestamp', 'timestamp', 'captured_at'], ''),
      ),
      tags: ['csv-import', if (label.isNotEmpty) 'dataset-label:$label'],
      flowFeatures: flowFeatures,
    );
  }

  /// Extract all 77 canonical flow features from a raw CSV row.
  ///
  /// Uses CIC-IDS2017 column aliases.  Only features that are present and
  /// parse to a valid finite double are included; the rest are omitted and
  /// will default to 0.0 inside the backend's _normalize_features().
  Map<String, double> _extractFlowFeatures(Map<String, String> row) {
    // Build a lowercase index of the row's keys for O(1) alias lookup.
    final rowIndex = <String, String>{};
    for (final key in row.keys) {
      rowIndex[key.trim().toLowerCase()] = key;
    }

    final result = <String, double>{};
    for (final entry in _cicAliases.entries) {
      final feature = entry.key;
      for (final alias in entry.value) {
        final rawKey = rowIndex[alias.trim().toLowerCase()];
        if (rawKey == null) continue;
        final rawVal = row[rawKey]?.trim() ?? '';
        if (rawVal.isEmpty ||
            rawVal.toLowerCase() == 'nan' ||
            rawVal.toLowerCase() == 'inf' ||
            rawVal.toLowerCase() == '-inf') {
          break;
        }
        final parsed = double.tryParse(rawVal.replaceAll(',', '.'));
        if (parsed != null && parsed.isFinite) {
          result[feature] = parsed;
        }
        break; // first alias match wins
      }
    }
    return result;
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
