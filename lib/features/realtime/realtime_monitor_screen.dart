import 'package:diploma_application_ml/core/theme/app_theme.dart';
import 'package:diploma_application_ml/domain/models/realtime_event.dart';
import 'package:diploma_application_ml/features/event_details/event_details_screen.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

class RealtimeMonitorScreen extends StatelessWidget {
  const RealtimeMonitorScreen({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: controller,
      builder: (context, _) => _RealtimeMonitorView(controller: controller),
    );
  }
}

class _RealtimeMonitorView extends StatelessWidget {
  const _RealtimeMonitorView({required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final palette = Theme.of(context).extension<StatusPalette>()!;
    final events = controller.realtimeEvents;
    final running = controller.realtimeRunning;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _Header(controller: controller, palette: palette),
        _StatsRow(controller: controller, palette: palette),
        const Divider(height: 1),
        Expanded(
          child: events.isEmpty
              ? _EmptyState(running: running)
              : _EventList(events: events, palette: palette, controller: controller),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Header with start/stop controls
// ---------------------------------------------------------------------------
class _Header extends StatefulWidget {
  const _Header({required this.controller, required this.palette});

  final AppController controller;
  final StatusPalette palette;

  @override
  State<_Header> createState() => _HeaderState();
}

class _HeaderState extends State<_Header> {
  String _selectedSource = 'synthetic';
  List<({String value, String label})> _interfaces = [];
  String? _selectedInterface;
  bool _loadingInterfaces = false;

  static const _sources = [
    ('synthetic', 'Synthetic (demo)'),
    ('pyshark', 'Live — pyshark'),
    ('scapy', 'Live — scapy'),
  ];

  bool get _needsInterface =>
      _selectedSource == 'pyshark' || _selectedSource == 'scapy';

  Future<void> _loadInterfaces(String source) async {
    setState(() {
      _loadingInterfaces = true;
      _interfaces = [];
      _selectedInterface = null;
    });
    final list =
        await widget.controller.fetchRealtimeInterfaces(source);
    if (!mounted) return;
    setState(() {
      _interfaces = list;
      _selectedInterface = list.isNotEmpty ? list.first.value : null;
      _loadingInterfaces = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final running = widget.controller.realtimeRunning;
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Real-time Monitor', style: theme.textTheme.headlineMedium),
          const SizedBox(height: 4),
          Text(
            'Live network traffic analysis with two-stage AI verification.',
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              if (!running) ...[
                DropdownButton<String>(
                  value: _selectedSource,
                  items: _sources
                      .map((s) => DropdownMenuItem(value: s.$1, child: Text(s.$2)))
                      .toList(),
                  onChanged: (v) {
                    setState(() => _selectedSource = v!);
                    if (v == 'pyshark' || v == 'scapy') _loadInterfaces(v!);
                  },
                ),
                if (_needsInterface) ...[
                  const SizedBox(width: 12),
                  if (_loadingInterfaces)
                    const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  else if (_interfaces.isNotEmpty)
                    DropdownButton<String>(
                      value: _selectedInterface,
                      hint: const Text('Select interface'),
                      items: _interfaces
                          .map((i) => DropdownMenuItem(
                                value: i.value,
                                child: Text(
                                  i.label,
                                  style: const TextStyle(fontSize: 13),
                                ),
                              ))
                          .toList(),
                      onChanged: (v) =>
                          setState(() => _selectedInterface = v),
                    )
                  else
                    const Text(
                      'No interfaces found',
                      style: TextStyle(fontSize: 13, color: Colors.orange),
                    ),
                ],
                const SizedBox(width: 12),
                FilledButton.icon(
                  onPressed: _needsInterface && _selectedInterface == null
                      ? null
                      : () => widget.controller.startRealtime(
                            source: _selectedSource,
                            interface: _selectedInterface,
                          ),
                  icon: const Icon(Icons.play_arrow),
                  label: const Text('Start'),
                ),
              ] else ...[
                Container(
                  width: 10,
                  height: 10,
                  decoration: const BoxDecoration(
                    color: Colors.green,
                    shape: BoxShape.circle,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  'Monitoring: ${widget.controller.realtimeSource}',
                  style: theme.textTheme.bodyMedium
                      ?.copyWith(fontWeight: FontWeight.w600),
                ),
                const Spacer(),
                OutlinedButton.icon(
                  onPressed: widget.controller.stopRealtime,
                  icon: const Icon(Icons.stop),
                  label: const Text('Stop'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: theme.colorScheme.error,
                    side: BorderSide(color: theme.colorScheme.error),
                  ),
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Summary stats row
// ---------------------------------------------------------------------------
class _StatsRow extends StatelessWidget {
  const _StatsRow({required this.controller, required this.palette});

  final AppController controller;
  final StatusPalette palette;

  @override
  Widget build(BuildContext context) {
    final total = controller.realtimeThreatCount + controller.realtimeBenignCount;
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 0, 20, 12),
      child: Wrap(
        spacing: 12,
        runSpacing: 8,
        children: [
          _StatChip(
            label: 'Total flows',
            value: '$total',
            color: Theme.of(context).colorScheme.primary,
          ),
          _StatChip(
            label: 'Threats',
            value: '${controller.realtimeThreatCount}',
            color: palette.verifiedThreat,
          ),
          _StatChip(
            label: 'Benign',
            value: '${controller.realtimeBenignCount}',
            color: palette.benign,
          ),
        ],
      ),
    );
  }
}

class _StatChip extends StatelessWidget {
  const _StatChip({required this.label, required this.value, required this.color});

  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            value,
            style: TextStyle(fontWeight: FontWeight.w700, color: color, fontSize: 18),
          ),
          const SizedBox(width: 6),
          Text(label, style: const TextStyle(fontSize: 13)),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------
class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.running});

  final bool running;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            running ? Icons.radar_outlined : Icons.play_circle_outline_rounded,
            size: 64,
            color: Theme.of(context).colorScheme.outline,
          ),
          const SizedBox(height: 16),
          Text(
            running
                ? 'Waiting for completed flows…'
                : 'Press Start to begin monitoring.',
            style: Theme.of(context).textTheme.bodyLarge,
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Scrollable list of flow results
// ---------------------------------------------------------------------------
class _EventList extends StatelessWidget {
  const _EventList({
    required this.events,
    required this.palette,
    required this.controller,
  });

  final List<RealtimeEvent> events;
  final StatusPalette palette;
  final AppController controller;

  @override
  Widget build(BuildContext context) {
    return ListView.separated(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      itemCount: events.length,
      separatorBuilder: (_, __) => const SizedBox(height: 4),
      itemBuilder: (context, i) => _EventTile(
        event: events[i],
        palette: palette,
        controller: controller,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Single flow tile — tapping opens EventDetailsScreen
// ---------------------------------------------------------------------------
class _EventTile extends StatelessWidget {
  const _EventTile({
    required this.event,
    required this.palette,
    required this.controller,
  });

  final RealtimeEvent event;
  final StatusPalette palette;
  final AppController controller;

  static final _timeFmt = DateFormat('HH:mm:ss');

  Color _statusColor(StatusPalette p) => switch (event.finalStatus) {
        'Verified Threat' => p.verifiedThreat,
        'Suspicious'      => p.suspicious,
        _                 => p.benign,
      };

  IconData _statusIcon() => switch (event.finalStatus) {
        'Verified Threat' => Icons.gpp_bad_outlined,
        'Suspicious'      => Icons.warning_amber_rounded,
        _                 => Icons.check_circle_outline,
      };

  void _openDetails(BuildContext context) {
    // The incident was inserted into controller.history with this ID
    final incidentId = 'rt-${event.processedAt.millisecondsSinceEpoch}';
    final incident = controller.history.firstWhere(
      (i) => i.event.id == incidentId,
      orElse: () => controller.history.first,
    );
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => EventDetailsScreen(
          controller: controller,
          incident: incident,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final color = _statusColor(palette);
    final theme = Theme.of(context);

    return Container(
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: ListTile(
        dense: true,
        leading: Icon(_statusIcon(), color: color, size: 22),
        title: Text(
          '${event.srcIp}:${event.srcPort}  →  ${event.dstIp}:${event.dstPort}',
          style: theme.textTheme.bodyMedium?.copyWith(
            fontFamily: 'monospace',
            fontWeight: FontWeight.w600,
          ),
        ),
        subtitle: Text(
          '${event.finalStatus}  •  '
          'det ${(event.detectorConfidence * 100).toStringAsFixed(0)}%  '
          'ver ${(event.verificationConfidence * 100).toStringAsFixed(0)}%  '
          'stab ${(event.detectorStability * 100).toStringAsFixed(0)}%',
          style: theme.textTheme.bodySmall,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              _timeFmt.format(event.processedAt),
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.outline,
              ),
            ),
            const SizedBox(width: 4),
            const Icon(Icons.chevron_right, size: 18),
          ],
        ),
        onTap: () => _openDetails(context),
      ),
    );
  }
}
