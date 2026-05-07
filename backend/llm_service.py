"""Shared LLM explanation service (Ollama).

Imported by both server.py (manual analysis) and realtime/pipeline.py
(streaming inference) so both paths generate async AI explanations.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
from typing import Any

from storage import (
    get_recent_events_by_ip,
    update_report_correlation_note,
    update_report_explanation,
    update_report_recommendations,
)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT_SEC = float(os.getenv("OLLAMA_TIMEOUT_SEC", "60"))

CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "10"))
CORRELATION_MIN_EVENTS = int(os.getenv("CORRELATION_MIN_EVENTS", "3"))

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_EXPLANATION_PROMPT_TEMPLATE = """Summarise this network security alert for an analyst. Write exactly 2-3 sentences in plain English.

Structure:
- Sentence 1: what was detected and the final verdict.
- Sentence 2: the main reason — one or two specific signals that drove the conclusion.
- Sentence 3 (only if needed): note any uncertainty or what made the case borderline.

Strict rules — violating any of these makes the output unusable:
1. Do NOT start with "I", "The system", "As a", "Based on", or "This alert".
2. Do NOT add any closing phrase: no "feel free to ask", no "let me know", no "I hope this helps", no "if you need more", no "please don't hesitate". The analysis ends with the last sentence, full stop.
3. Do NOT use raw variable names or jargon: write "high packet rate" not "flow_packets_per_s", write "traffic volume" not "bytes_transferred_kb".
4. Output nothing except the 2-3 sentences.

Alert data:
Verdict: {status}
Detected as: {detector_label} (detector confidence: {detector_confidence})
Warning signs: {triggered_indicators}
Verification summary: {verification_summary}
Overall confidence: {certain}
Key traffic signals: {top_signals}
Verification checks:
{checks_detail}"""

_RECOMMENDATIONS_PROMPT_TEMPLATE = """Write a numbered list of 3-5 investigation steps for this suspicious network event.

Strict rules — violating any of these makes the output unusable:
1. Start each step with an action verb: Check, Block, Inspect, Verify, Review, Isolate, Correlate.
2. Use the actual IPs, ports, and threat type from the data — be specific, not generic.
3. Maximum 15 words per step.
4. Do NOT write any introduction, conclusion, or closing remark. Output ONLY the numbered list — nothing before step 1, nothing after the last step.
5. No "feel free to ask", no "let me know", no "I hope this helps". The list is the complete output.

Event data:
Source: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})
Threat type: {detector_label}
Warning signs: {triggered_indicators}
Active flags: {flags}
Failed checks: {failed_checks}
Key signals: {top_signals}"""


_CORRELATION_PROMPT_TEMPLATE = """Analyse this cluster of network events from one source IP. Write exactly 2-3 sentences.

Rules — violating any makes the output unusable:
1. Start with the source IP, event count, and time window.
2. Identify the pattern: port scan, brute-force, C2 beacon, data exfil, or inconclusive.
3. End with a threat urgency level: low / medium / high.
4. Do NOT write "I", "The system", "Based on", or any closing phrase.
5. Output only the 2-3 sentences — nothing else.

Source IP: {src_ip}
Events in last {window_minutes} min: {event_count}
Time span: {time_span}s
Verdicts: {status_summary}
Destination ports: {dst_ports}
Confidence range: {conf_min}%→{conf_max}%
Indicators across all events: {all_indicators}
Event timeline:
{events_detail}

OUTPUT: 2-3 sentences only."""


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def _build_explanation_prompt(
    status: str,
    probability: float,
    verification_details: dict[str, Any],
    detector_output: dict[str, Any] | None = None,
) -> str:
    det = detector_output or {}
    uncertainty = verification_details.get("uncertainty") or {}
    checks_raw = verification_details.get("checks") or []
    perturbation = verification_details.get("perturbation_analysis") or {}
    top_5 = (verification_details.get("feature_importance") or {}).get("top_5") or []

    checks_detail = "\n".join(
        f"  {'PASS' if c.get('passed') else 'FAIL'}: {c.get('title', '?')}"
        for c in checks_raw
    ) or "  n/a"
    top_signals = ", ".join(
        f['feature'].replace("_", " ")
        for f in top_5
    ) or "n/a"
    triggered = det.get("triggered_indicators") or []
    is_uncertain = uncertainty.get("is_uncertain", False)
    confidence_pct = int(float(det.get("confidence", 0.0)) * 100)

    return _EXPLANATION_PROMPT_TEMPLATE.format(
        detector_label=det.get("label", "unknown"),
        detector_confidence=f"{confidence_pct}%",
        triggered_indicators=", ".join(triggered) if triggered else "none detected",
        status=status,
        verification_score=f"{float(probability):.3f}",
        verification_summary=verification_details.get("summary", "n/a"),
        certain="high confidence" if not is_uncertain else "uncertain — needs analyst review",
        checks_detail=checks_detail,
        uncertainty_std=round(float(uncertainty.get("std_deviation", 0.0)), 3),
        consistency=round(float(perturbation.get("label_consistency_ratio", 0.0)), 2),
        confidence_drop=round(float(perturbation.get("confidence_drop", 0.0)), 3),
        top_signals=top_signals,
    )


def _build_recommendations_prompt(
    probability: float,
    event: dict[str, Any],
    verification_details: dict[str, Any],
    detector_output: dict[str, Any] | None = None,
) -> str:
    det = detector_output or {}
    uncertainty = verification_details.get("uncertainty") or {}
    checks_raw = verification_details.get("checks") or []
    failed_checks_line = ", ".join(
        f"{c.get('title', '?')} ({round(float(c.get('score', 0)), 2)})"
        for c in checks_raw
        if not c.get("passed")
    ) or "none"
    event_context = verification_details.get("event_context") or {}
    active_flags = [
        k for k in ("known_bad_source", "off_hours_activity", "repeated_attempts")
        if event_context.get(k)
    ]
    perturbation = verification_details.get("perturbation_analysis") or {}
    top_5 = (verification_details.get("feature_importance") or {}).get("top_5") or []
    top_signals = ", ".join(
        f"{f['feature']} ({'+' if f['attribution'] >= 0 else ''}{round(f['attribution'], 2)})"
        for f in top_5
    ) or "n/a"
    triggered = det.get("triggered_indicators") or []

    return _RECOMMENDATIONS_PROMPT_TEMPLATE.format(
        src_ip=event.get("source_ip") or event.get("src_ip") or "?",
        dst_ip=event.get("destination_ip") or event.get("dst_ip") or "?",
        protocol=event.get("protocol") or "unknown",
        src_port=event.get("source_port") or event.get("src_port") or "?",
        dst_port=event.get("destination_port") or event.get("dst_port") or "?",
        detector_label=det.get("label", "unknown"),
        detector_confidence=f"{float(det.get('confidence', 0.0)):.3f}",
        triggered_indicators=", ".join(triggered) if triggered else "none",
        verification_score=f"{float(probability):.3f}",
        uncertainty_std=round(float(uncertainty.get("std_deviation", 0.0)), 3),
        anomaly_score=round(float(event.get("anomaly_score") or 0.0), 3),
        flags=", ".join(active_flags) if active_flags else "none",
        failed_checks=failed_checks_line,
        consistency=round(float(perturbation.get("label_consistency_ratio", 0.0)), 2),
        confidence_drop=round(float(perturbation.get("confidence_drop", 0.0)), 3),
        top_signals=top_signals,
    )


def _build_correlation_prompt(src_ip: str, events: list[dict], window_minutes: int) -> str:
    from datetime import datetime as _dt

    statuses = [e.get("final_status") or "Unknown" for e in events]
    status_counts: dict[str, int] = {}
    for s in statuses:
        status_counts[s] = status_counts.get(s, 0) + 1
    status_summary = ", ".join(f"{cnt}× {st}" for st, cnt in status_counts.items())

    dst_ports = sorted({
        str((e.get("event_snapshot") or {}).get("destination_port", ""))
        for e in events
        if (e.get("event_snapshot") or {}).get("destination_port")
    })

    confidences = [float(e.get("confidence") or 0.0) for e in events]
    conf_min = int(min(confidences) * 100)
    conf_max = int(max(confidences) * 100)

    seen_indicators: set[str] = set()
    all_indicators: list[str] = []
    for e in events:
        for ind in ((e.get("detector_output") or {}).get("triggered_indicators") or []):
            if ind not in seen_indicators:
                all_indicators.append(ind)
                seen_indicators.add(ind)

    timestamps = [e.get("created_at") or "" for e in events]
    try:
        t0 = _dt.fromisoformat(timestamps[0].replace("Z", "+00:00"))
        t1 = _dt.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
        time_span = int((t1 - t0).total_seconds())
    except Exception:
        time_span = 0

    lines = []
    for e in events:
        snap = e.get("event_snapshot") or {}
        lines.append(
            f"  {(e.get('created_at') or '')[:19]}"
            f" | {(e.get('final_status') or '?'):20s}"
            f" | port={snap.get('destination_port', '?')}"
            f" conf={int(float(e.get('confidence') or 0) * 100)}%"
        )

    return _CORRELATION_PROMPT_TEMPLATE.format(
        src_ip=src_ip,
        window_minutes=window_minutes,
        event_count=len(events),
        time_span=time_span,
        status_summary=status_summary,
        dst_ports=", ".join(dst_ports) if dst_ports else "unknown",
        conf_min=conf_min,
        conf_max=conf_max,
        all_indicators=", ".join(all_indicators) if all_indicators else "none",
        events_detail="\n".join(lines),
    )


# ---------------------------------------------------------------------------
# Ollama HTTP client
# ---------------------------------------------------------------------------

def ollama_reachable() -> bool:
    """Quick ping — 3 s timeout. Used to set explanation_pending in responses."""
    import urllib.request

    tags_url = OLLAMA_URL.rsplit("/api/generate", 1)[0] + "/api/tags"
    try:
        req = urllib.request.Request(tags_url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ollama_complete(prompt: str) -> str:
    import urllib.request

    body = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT_SEC) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return (payload.get("response") or "").strip()


# ---------------------------------------------------------------------------
# Artifact generation
# ---------------------------------------------------------------------------

def generate_llm_artifacts(
    report_id: int,
    event: dict[str, Any],
    verification_details: dict[str, Any],
    status: str,
    probability: float,
    detector_output: dict[str, Any] | None = None,
) -> None:
    """Generate explanation (always) and recommendations (Suspicious only). Silent on failure."""
    try:
        explanation = _ollama_complete(
            _build_explanation_prompt(status, probability, verification_details, detector_output)
        )
        if explanation:
            update_report_explanation(report_id, explanation)
    except Exception as exc:  # noqa: BLE001
        print(f"[ollama] explanation for report {report_id} failed: {exc}", file=sys.stderr)

    if status == "Suspicious":
        try:
            recommendations = _ollama_complete(
                _build_recommendations_prompt(probability, event, verification_details, detector_output)
            )
            if recommendations:
                update_report_recommendations(report_id, recommendations)
        except Exception as exc:  # noqa: BLE001
            print(f"[ollama] recommendations for report {report_id} failed: {exc}", file=sys.stderr)


def generate_correlation_note(
    report_id: int,
    src_ip: str,
    events: list[dict[str, Any]],
    window_minutes: int,
) -> None:
    """Generate and persist a cross-event correlation note. Silent on failure."""
    try:
        note = _ollama_complete(_build_correlation_prompt(src_ip, events, window_minutes))
        if note:
            update_report_correlation_note(report_id, note)
    except Exception as exc:  # noqa: BLE001
        print(f"[ollama] correlation for report {report_id} failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Worker queue — one daemon thread, one Ollama request at a time
# ---------------------------------------------------------------------------

_llm_queue: queue.Queue = queue.Queue()


def _llm_worker() -> None:
    while True:
        task = _llm_queue.get()
        try:
            task_type, *args = task
            if task_type == "artifacts":
                generate_llm_artifacts(*args)
            elif task_type == "correlation":
                generate_correlation_note(*args)
        finally:
            _llm_queue.task_done()


threading.Thread(target=_llm_worker, daemon=True, name="llm-worker").start()


def enqueue_llm_artifacts(
    report_id: int,
    event: dict[str, Any],
    verification_details: dict[str, Any],
    status: str,
    probability: float,
    detector_output: dict[str, Any] | None = None,
) -> None:
    """Put an LLM artifacts task on the queue. Returns immediately."""
    _llm_queue.put(("artifacts", report_id, event, verification_details, status, probability, detector_output))


def enqueue_correlation_check(report_id: int, src_ip: str) -> bool:
    """Query recent events for src_ip; enqueue correlation if threshold is met.

    Returns True if a correlation task was queued.
    Threshold: CORRELATION_MIN_EVENTS events in CORRELATION_WINDOW_MINUTES, at least 1 non-benign.
    """
    if not src_ip or src_ip in ("0.0.0.0", "?", "unknown"):
        return False
    events = get_recent_events_by_ip(src_ip, minutes=CORRELATION_WINDOW_MINUTES)
    if len(events) < CORRELATION_MIN_EVENTS:
        return False
    if not any(e.get("final_status") != "Benign" for e in events):
        return False
    _llm_queue.put(("correlation", report_id, src_ip, events, CORRELATION_WINDOW_MINUTES))
    return True
