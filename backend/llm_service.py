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

from storage import update_report_explanation, update_report_recommendations

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT_SEC = float(os.getenv("OLLAMA_TIMEOUT_SEC", "60"))

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_EXPLANATION_PROMPT_TEMPLATE = """Summarise this IDS result in 2-3 sentences. Write like a log entry: direct, factual, no filler.
Rules: no "As a...", no "I would", no "it is worth noting", no hedging. Start with the verdict.

Stage 1 · RF Detector: {detector_label} (conf={detector_confidence}) indicators={triggered_indicators}
Stage 2 · Verdict: {status} score={verification_score} certain={certain}
Summary: {verification_summary}
Checks:
{checks_detail}
std={uncertainty_std} consistency={consistency} drop={confidence_drop}
Top signals: {top_signals}

OUTPUT: 2-3 plain sentences, no bullet points, no intro phrases."""

_RECOMMENDATIONS_PROMPT_TEMPLATE = """Event is SUSPICIOUS. List 3-5 investigation steps based ONLY on the data below.
Rules: bullets only, max 12 words each, no intro, no "I would", no generic advice like "monitor the network".

Traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={protocol}
Detector: {detector_label} conf={detector_confidence} anomaly={anomaly_score}
Indicators: {triggered_indicators}
Flags: {flags}
Failed checks: {failed_checks}
score={verification_score} std={uncertainty_std} consistency={consistency} drop={confidence_drop}
Top signals: {top_signals}

OUTPUT: bullet list only, no preamble."""


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
        f"  {'✓' if c.get('passed') else '✗'} {c.get('title', '?')}"
        f"  score={round(float(c.get('score', 0)), 2)}"
        f"  weight={round(float(c.get('weight', 1.0)), 2)}"
        f"  evidence={'; '.join((c.get('evidence') or [])[:2]) or 'n/a'}"
        for c in checks_raw
    ) or "  n/a"
    top_signals = ", ".join(
        f"{f['feature']} ({'+' if f['attribution'] >= 0 else ''}{round(f['attribution'], 2)})"
        for f in top_5
    ) or "n/a"
    triggered = det.get("triggered_indicators") or []

    return _EXPLANATION_PROMPT_TEMPLATE.format(
        detector_label=det.get("label", "unknown"),
        detector_confidence=f"{float(det.get('confidence', 0.0)):.3f}",
        triggered_indicators=", ".join(triggered) if triggered else "none",
        status=status,
        verification_score=f"{float(probability):.3f}",
        verification_summary=verification_details.get("summary", "n/a"),
        certain=str(not uncertainty.get("is_uncertain", False)),
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


# ---------------------------------------------------------------------------
# Worker queue — one daemon thread, one Ollama request at a time
# ---------------------------------------------------------------------------

_llm_queue: queue.Queue = queue.Queue()


def _llm_worker() -> None:
    while True:
        task = _llm_queue.get()
        try:
            generate_llm_artifacts(*task)
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
    """Put an LLM generation task on the queue. Returns immediately."""
    _llm_queue.put((report_id, event, verification_details, status, probability, detector_output))
