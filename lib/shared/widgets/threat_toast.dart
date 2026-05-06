import 'dart:async';

import 'package:diploma_application_ml/domain/models/realtime_event.dart';
import 'package:flutter/material.dart';

/// Wraps [child] and shows persistent bottom-right alerts for Verified Threat events.
/// Toasts require explicit user dismissal — they do NOT auto-close.
class ThreatToastOverlay extends StatefulWidget {
  const ThreatToastOverlay({
    super.key,
    required this.stream,
    required this.child,
  });

  final Stream<RealtimeEvent> stream;
  final Widget child;

  @override
  State<ThreatToastOverlay> createState() => _ThreatToastOverlayState();
}

class _ThreatToastOverlayState extends State<ThreatToastOverlay> {
  final List<_ToastEntry> _toasts = [];
  StreamSubscription<RealtimeEvent>? _sub;

  @override
  void initState() {
    super.initState();
    _sub = widget.stream.listen(_onThreat);
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  void _onThreat(RealtimeEvent event) {
    if (!mounted) return;
    final id = UniqueKey();
    setState(() {
      // Keep at most 3 simultaneous alerts; silently drop the oldest if full.
      if (_toasts.length >= 3) {
        _toasts.removeAt(0);
      }
      _toasts.add(_ToastEntry(id: id, event: event));
    });
  }

  void _remove(Key id) {
    if (!mounted) return;
    setState(() => _toasts.removeWhere((t) => t.id == id));
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        widget.child,
        Positioned(
          bottom: 72,
          right: 16,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: _toasts
                .map(
                  (t) => Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: _ThreatToastCard(
                      entry: t,
                      onDismiss: () => _remove(t.id),
                    ),
                  ),
                )
                .toList(),
          ),
        ),
      ],
    );
  }
}

class _ToastEntry {
  _ToastEntry({required this.id, required this.event});
  final Key id;
  final RealtimeEvent event;
}

class _ThreatToastCard extends StatefulWidget {
  const _ThreatToastCard({required this.entry, required this.onDismiss});

  final _ToastEntry entry;
  final VoidCallback onDismiss;

  @override
  State<_ThreatToastCard> createState() => _ThreatToastCardState();
}

class _ThreatToastCardState extends State<_ThreatToastCard>
    with SingleTickerProviderStateMixin {
  late final AnimationController _anim;
  late final Animation<Offset> _slide;
  late final Animation<double> _fade;

  @override
  void initState() {
    super.initState();
    _anim = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 280),
    )..forward();
    _slide = Tween<Offset>(
      begin: const Offset(0.4, 0),
      end: Offset.zero,
    ).animate(CurvedAnimation(parent: _anim, curve: Curves.easeOut));
    _fade = CurvedAnimation(parent: _anim, curve: Curves.easeOut);
  }

  @override
  void dispose() {
    _anim.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final e = widget.entry.event;
    final detConf = (e.detectorConfidence * 100).toStringAsFixed(0);
    final verConf = (e.verificationConfidence * 100).toStringAsFixed(0);
    final t = e.processedAt;
    final timeStr =
        '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';
    final reportLabel = e.reportId != null ? '#${e.reportId}' : 'live';

    return SlideTransition(
      position: _slide,
      child: FadeTransition(
        opacity: _fade,
        child: Material(
          elevation: 10,
          borderRadius: BorderRadius.circular(12),
          color: const Color(0xFFB42318),
          child: SizedBox(
            width: 340,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(14, 12, 8, 12),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Padding(
                    padding: EdgeInsets.only(top: 1),
                    child: Icon(
                      Icons.gpp_bad,
                      color: Colors.white,
                      size: 22,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Text(
                              'VERIFIED THREAT',
                              style: TextStyle(
                                color: Colors.white,
                                fontWeight: FontWeight.w800,
                                fontSize: 12,
                                letterSpacing: 0.5,
                              ),
                            ),
                            const SizedBox(width: 6),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 6, vertical: 2),
                              decoration: BoxDecoration(
                                color: Colors.white.withValues(alpha: 0.18),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(
                                reportLabel,
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 10,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 3),
                        Text(
                          '${e.srcIp}:${e.srcPort}  →  ${e.dstIp}:${e.dstPort}',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 12,
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          'det $detConf%  •  ver $verConf%  •  ${e.detectorLabel}',
                          style: const TextStyle(
                            color: Colors.white70,
                            fontSize: 11,
                          ),
                        ),
                        if (e.triggeredIndicators.isNotEmpty) ...[
                          const SizedBox(height: 3),
                          Text(
                            e.triggeredIndicators.take(2).join(', '),
                            style: const TextStyle(
                              color: Colors.white60,
                              fontSize: 10,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                        const SizedBox(height: 3),
                        Text(
                          timeStr,
                          style: const TextStyle(
                            color: Colors.white38,
                            fontSize: 10,
                          ),
                        ),
                      ],
                    ),
                  ),
                  // Dismiss requires explicit user action — no auto-close timer.
                  IconButton(
                    onPressed: widget.onDismiss,
                    icon: const Icon(
                      Icons.close,
                      color: Colors.white60,
                      size: 18,
                    ),
                    tooltip: 'Dismiss',
                    padding: const EdgeInsets.only(left: 4),
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
