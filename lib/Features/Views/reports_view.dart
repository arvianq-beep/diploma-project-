import 'dart:convert';
import 'dart:io';

import 'package:diploma_application_ml/Models/reports_models.dart';
import 'package:diploma_application_ml/Serives/api_service.dart';
import 'package:flutter/material.dart';
import 'package:open_file/open_file.dart';
import 'package:path_provider/path_provider.dart';




class ReportsView extends StatefulWidget {
  final ApiService api;
  const ReportsView({super.key, required this.api});

  @override
  State<ReportsView> createState() => _ReportsViewState();
}

class _ReportsViewState extends State<ReportsView> {
  bool _loading = true;
  String? _error;

  ReportsResponse? _data;
  DateTimeRange? _range;

  @override
  void initState() {
    super.initState();
    _load();
  }

  String? _fromIso() => _range?.start.toUtc().toIso8601String();
  String? _toIso() => _range?.end.toUtc().toIso8601String();

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final res = await widget.api.getReports(
        fromIsoUtc: _fromIso(),
        toIsoUtc: _toIso(),
        limit: 50,
        offset: 0,
      );
      setState(() => _data = res);
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _pickRange() async {
    final now = DateTime.now();
    final picked = await showDateRangePicker(
      context: context,
      firstDate: DateTime(now.year - 1),
      lastDate: DateTime(now.year + 1),
      initialDateRange: _range,
    );
    if (picked != null) {
      setState(() => _range = picked);
      await _load();
    }
  }

  Future<void> _export(String format) async {
    try {
      final bytes = await widget.api.exportReports(
        format: format,
        fromIsoUtc: _fromIso(),
        toIsoUtc: _toIso(),
      );

      final dir = await getApplicationDocumentsDirectory();
      final ts = DateTime.now().millisecondsSinceEpoch;
      final file = File('${dir.path}/reports_$ts.$format');
      await file.writeAsBytes(bytes);

      await OpenFile.open(file.path);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Export error: $e')),
      );
    }
  }

  void _openDetails(ReportItem item) {
    final pretty = const JsonEncoder.withIndent('  ').convert({
      'id': item.id,
      'created_at': item.createdAt,
      'label': item.label,
      'confidence': item.confidence,
      'decision_status': item.decisionStatus,
      'decision_reason': item.decisionReason,
      'traffic_context': item.trafficContext,
      'raw_input': item.rawInput,
    });

    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Report details'),
        content: SingleChildScrollView(
          child: SelectableText(pretty),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final rangeText = (_range == null)
        ? 'All time'
        : '${_range!.start.toString().substring(0, 10)} → ${_range!.end.toString().substring(0, 10)}';

    return Scaffold(
      appBar: AppBar(
        title: const Text('Reports'),
        actions: [
          IconButton(
            tooltip: 'Pick period',
            onPressed: _pickRange,
            icon: const Icon(Icons.date_range),
          ),
          IconButton(
            tooltip: 'Reload',
            onPressed: _load,
            icon: const Icon(Icons.refresh),
          ),
          PopupMenuButton<String>(
            onSelected: _export,
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'csv', child: Text('Export CSV')),
              PopupMenuItem(value: 'json', child: Text('Export JSON')),
            ],
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : (_error != null)
              ? Center(child: Text('Error: $_error'))
              : _data == null
                  ? const Center(child: Text('No data'))
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Padding(
                          padding: const EdgeInsets.all(12),
                          child: Text(
                            'Period: $rangeText',
                            style: Theme.of(context).textTheme.bodyMedium,
                          ),
                        ),
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 12),
                          child: Wrap(
                            spacing: 12,
                            runSpacing: 12,
                            children: [
                              _StatChip(label: 'Total', value: _data!.summary.total),
                              _StatChip(label: 'Normal', value: _data!.summary.normal),
                              _StatChip(label: 'Non-normal', value: _data!.summary.nonNormal),
                              _StatChip(label: 'Verified', value: _data!.summary.verifiedThreat),
                              _StatChip(label: 'Suspicious', value: _data!.summary.suspicious),
                            ],
                          ),
                        ),
                        const SizedBox(height: 12),
                        Expanded(
                          child: ListView.separated(
                            itemCount: _data!.items.length,
                            separatorBuilder: (_, __) => const Divider(height: 1),
                            itemBuilder: (context, i) {
                              final it = _data!.items[i];
                              return ListTile(
                                title: Text('${it.decisionStatus}'),
                                subtitle: Text('${it.label} • conf=${it.confidence.toStringAsFixed(3)} • ${it.createdAt}'),
                                trailing: const Icon(Icons.chevron_right),
                                onTap: () => _openDetails(it),
                              );
                            },
                          ),
                        ),
                      ],
                    ),
    );
  }
}

class _StatChip extends StatelessWidget {
  final String label;
  final int value;
  const _StatChip({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Chip(
      label: Text('$label: $value'),
    );
  }
}
