from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Matches a bare GUID like  256FC667-8A70-46BB-8C44-6AE50447293F
_GUID_RE = re.compile(
    r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
)


def _normalize_interface(iface: str) -> str:
    """On Windows, wrap a bare GUID into the Npcap device path.

    '256FC667-8A70-...' → r'\\Device\\NPF_{256FC667-8A70-...}'
    On macOS/Linux or when the full path is already present, return unchanged.
    """
    iface = iface.strip()
    if sys.platform == "win32" and _GUID_RE.match(iface):
        return rf"\Device\NPF_{{{iface}}}"
    return iface

from flask import Flask, Response, jsonify, request, stream_with_context
from flask_cors import CORS

from datasets_storage import list_datasets, save_uploaded_dataset
from ml.inference import MLPredictor
from ml.schema import CANONICAL_FEATURES, CIC_COLUMN_ALIASES
from storage import (
    ANALYST_VERDICTS,
    add_analyst_feedback,
    get_conn,
    get_report_by_id,
    init_db,
    insert_report,
    update_report_explanation,
    update_report_recommendations,
)
from verification.inference import SecureDecisionVerificationService


app = Flask(__name__)
CORS(app)

init_db()

predictor: MLPredictor | None = None
verifier: SecureDecisionVerificationService | None = None

# ---------------------------------------------------------------------------
# Real-time monitor — single global instance, created lazily on /start
# ---------------------------------------------------------------------------
_monitor_lock = threading.Lock()
_rt_monitor = None


def _get_monitor():
    return _rt_monitor


def _set_monitor(m):
    global _rt_monitor
    _rt_monitor = m


def get_predictor() -> MLPredictor:
    global predictor
    if predictor is None:
        predictor = MLPredictor()
    return predictor


def get_verifier() -> SecureDecisionVerificationService:
    global verifier
    predictor_instance = get_predictor()
    if verifier is None:
        verifier = SecureDecisionVerificationService(predictor_instance)
    return verifier


def _json_payload():
    return request.get_json(silent=True) or {}


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y"}:
            return True
        if normalized in {"false", "0", "no", "n", ""}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _normalize_event(event_payload: dict, fallback_id: str | None = None) -> dict:
    event_id = str(event_payload.get("id") or fallback_id or uuid.uuid4())
    captured_raw = event_payload.get("captured_at") or event_payload.get("timestamp")
    captured_at = captured_raw or datetime.now(timezone.utc).isoformat()
    direct_features = {
        feature_name: max(_safe_float(event_payload.get(feature_name)), 0.0)
        for feature_name in CANONICAL_FEATURES
        if feature_name in event_payload
    }
    derived_duration = max(
        _safe_float(event_payload.get("duration_seconds")),
        _safe_float(event_payload.get("duration")),
        _safe_float(event_payload.get("flow_duration")),
        0.0,
    )
    derived_packets_per_second = max(
        _safe_float(event_payload.get("packets_per_second")),
        _safe_float(event_payload.get("flow_packets_per_s")),
        0.0,
    )
    derived_bytes_per_second = max(
        _safe_float(event_payload.get("bytes_per_second")),
        _safe_float(event_payload.get("flow_bytes_per_s")),
        0.0,
    )
    derived_bytes_kb = max(
        _safe_float(event_payload.get("bytes_transferred_kb")),
        (
            _safe_float(event_payload.get("total_length_fwd_packets"))
            + _safe_float(event_payload.get("total_length_bwd_packets"))
        )
        / 1024.0,
    )
    if derived_bytes_kb == 0.0 and derived_duration > 0 and derived_bytes_per_second > 0:
        derived_bytes_kb = (derived_bytes_per_second * derived_duration) / 1024.0

    normalized_event = {
        "id": event_id,
        "title": str(event_payload.get("title", f"Imported event {event_id}")),
        "description": str(event_payload.get("description", "Network event submitted for ML analysis.")),
        "source_ip": str(event_payload.get("source_ip", "0.0.0.0")),
        "destination_ip": str(event_payload.get("destination_ip", "0.0.0.0")),
        "source_port": _safe_int(event_payload.get("source_port", 0)),
        "destination_port": _safe_int(
            event_payload.get("destination_port", direct_features.get("destination_port", 0))
        ),
        "protocol": str(event_payload.get("protocol", "UNKNOWN")),
        "bytes_transferred_kb": derived_bytes_kb,
        "duration_seconds": derived_duration,
        "packets_per_second": derived_packets_per_second,
        "failed_logins": _safe_int(event_payload.get("failed_logins", 0)),
        "anomaly_score": _safe_float(event_payload.get("anomaly_score", 0.0)),
        "context_risk_score": _safe_float(event_payload.get("context_risk_score", 0.0)),
        "known_bad_source": _safe_bool(event_payload.get("known_bad_source", False)),
        "off_hours_activity": _safe_bool(event_payload.get("off_hours_activity", False)),
        "repeated_attempts": _safe_bool(event_payload.get("repeated_attempts", False)),
        "sample_source": str(event_payload.get("sample_source", "Backend API")),
        "captured_at": captured_at,
        "tags": event_payload.get("tags", []),
    }
    normalized_event.update(direct_features)
    return normalized_event


# ---------------------------------------------------------------------------
# LLM explanation (Ollama) — see llm_service.py for implementation.
# ---------------------------------------------------------------------------
from llm_service import enqueue_llm_artifacts, ollama_reachable


def _analysis_response(event_payload: dict) -> dict:
    predictor_instance = get_predictor()
    verifier_instance = get_verifier()
    normalized_event = _normalize_event(event_payload)
    detector_output = predictor_instance.predict_from_event(normalized_event)
    verification = verifier_instance.evaluate(normalized_event, detector_output)

    response = {
        "event_id": normalized_event["id"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event": normalized_event,
        "threat_type": verification.threat_type,
        "is_threat": verification.is_threat,
        "ai_confidence": verification.ai_confidence,
        "detector_label": verification.detector_label,
        "detector_details": verification.detector_details,
        "verification_confidence": verification.verification_confidence,
        "is_verified": verification.is_verified,
        "verification_details": verification.verification_details,
        "final_decision_status": verification.final_decision_status,
        "recommended_action": verification.recommended_action,
        "model_available": verification.model_available,
        "detector_model_version": verification.detector_model_version,
        "verifier_model_version": verification.verifier_model_version,
        "feature_snapshot": verification.feature_snapshot,
        "prediction": {
            "label": detector_output.label,
            "confidence": detector_output.confidence,
            "stability_score": detector_output.stability_score,
            "model_version": detector_output.model_version,
            "reasoning": detector_output.reasoning,
            "alternative_hypothesis": detector_output.alternative_hypothesis,
            "triggered_indicators": detector_output.triggered_indicators,
            "feature_snapshot": detector_output.feature_snapshot,
            "model_available": predictor_instance.available,
        },
    }

    llm_available = ollama_reachable()
    response["explanation_pending"] = llm_available

    report_id = insert_report(
        event_id=normalized_event["id"],
        label=detector_output.label,
        confidence=detector_output.confidence,
        decision_status=verification.final_decision_status,
        decision_reason=verification.verification_details.get("summary"),
        final_status=verification.final_decision_status,
        recommended_action=verification.recommended_action,
        detector_output=response["prediction"],
        verification_output={
            "verification_confidence": verification.verification_confidence,
            "is_verified": verification.is_verified,
            "verification_details": verification.verification_details,
            "verifier_model_version": verification.verifier_model_version,
        },
        final_decision={
            "status": verification.final_decision_status,
            "recommended_action": verification.recommended_action,
            "threat_type": verification.threat_type,
            "feature_snapshot": verification.feature_snapshot,
        },
        event_snapshot=normalized_event,
        traffic_context={
            "event": normalized_event,
            "prediction": response["prediction"],
            "verification": response["verification_details"],
        },
        raw_input=event_payload,
    )
    response["report_id"] = report_id

    if llm_available:
        enqueue_llm_artifacts(
            report_id,
            normalized_event,
            verification.verification_details,
            verification.final_decision_status,
            verification.verification_confidence,
            response["prediction"],
        )

    return response


def _csv_dict_reader_from_upload(file_storage):
    body = file_storage.stream.read().decode("utf-8", errors="ignore")
    file_storage.stream.seek(0)
    return csv.DictReader(io.StringIO(body))


def _event_from_csv_row(row_index: int, row: dict[str, str], filename: str) -> dict:
    def normalize_protocol(value: str) -> str:
        normalized = str(value).strip()
        return {
            "6": "TCP",
            "17": "UDP",
            "1": "ICMP",
        }.get(normalized, normalized.upper() if normalized else "UNKNOWN")

    def read(*keys, default=""):
        for key in keys:
            if key in row and str(row[key]).strip() != "":
                return row[key]
        return default

    def read_float(*keys, default=0.0):
        value = read(*keys, default=default)
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    def read_int(*keys, default=0):
        value = read(*keys, default=default)
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return int(default)

    duration = read_float("duration_seconds", "duration", "dur", "Flow Duration", default=1.0)
    if duration > 10000:
        duration = duration / 1_000_000.0

    bytes_kb = read_float(
        "bytes_transferred_kb",
        "bytes",
        "flow_bytes",
        "sbytes",
        "Total Length of Fwd Packets",
        default=0.0,
    ) / 1024.0
    flow_bytes_per_second = read_float(
        "flow_bytes_per_s", "Flow Bytes/s", "Flow Byts/s", "bytes_per_second", "flow_bytes_per_second", default=0.0
    )
    if bytes_kb == 0.0 and flow_bytes_per_second > 0 and duration > 0:
        bytes_kb = (flow_bytes_per_second * duration) / 1024.0
    forward_packets = read_float(
        "forward_packets", "spkts", "Tot Fwd Pkts", "Total Fwd Packets", default=0.0
    )
    backward_packets = read_float(
        "backward_packets", "dpkts", "Tot Bwd Pkts", "Total Backward Packets", default=0.0
    )
    packets_per_second = read_float(
        "flow_packets_per_s", "packets_per_second", "Flow Packets/s", "Flow Pkts/s", "rate", default=0.0
    )
    if packets_per_second == 0.0 and duration > 0:
        total_packets = forward_packets + backward_packets
        packets_per_second = total_packets / duration if duration else 0.0

    protocol = normalize_protocol(read("protocol", "proto", "Protocol", default="UNKNOWN"))
    source_ip = read("source_ip", "srcip", "Src IP", "Source IP", default="0.0.0.0")
    destination_ip = read("destination_ip", "dstip", "Dst IP", "Destination IP", default="0.0.0.0")
    source_port = read_int("source_port", "sport", "Src Port", "Source Port", default=0)
    destination_port = read_int("destination_port", "dsport", "Destination Port", "Dst Port", default=0)
    label = read("Label", "label", "attack_cat", default="")

    # Resolve canonical features directly from CSV columns using CIC_COLUMN_ALIASES.
    # Any feature resolved here will be picked up as a direct_feature in _normalize_event,
    # bypassing the lossy legacy compatibility approximation for that field.
    canonical_features: dict[str, float] = {}
    for canonical_name, aliases in CIC_COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in row and str(row[alias]).strip() != "":
                try:
                    canonical_features[canonical_name] = max(float(row[alias]), 0.0)
                except (TypeError, ValueError):
                    pass
                break

    event: dict = {
        "id": f"csv-{row_index}",
        "title": f"CSV Event {row_index}",
        "description": f"Imported from {filename}" if not label else f"Imported from {filename} with dataset label {label}",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "bytes_transferred_kb": max(bytes_kb, 0.0),
        "duration_seconds": max(duration, 0.0),
        "packets_per_second": max(packets_per_second, 0.0),
        "failed_logins": read_int("failed_logins", default=0),
        "anomaly_score": min(max(read_float("anomaly_score", default=0.0), 0.0), 1.0),
        "context_risk_score": min(max(read_float("context_risk_score", default=0.0), 0.0), 1.0),
        "known_bad_source": str(read("known_bad_source", default="false")).lower() == "true" or source_ip.startswith(("185.", "45.")),
        "off_hours_activity": str(read("off_hours_activity", default="false")).lower() == "true",
        "repeated_attempts": str(read("repeated_attempts", default="false")).lower() == "true" or packets_per_second > 400 or destination_port == 22,
        "sample_source": f"CSV Import: {filename}",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "tags": ["csv-import", *([f"dataset-label:{label}"] if label else [])],
    }
    # Canonical features are written last so they are never overwritten by the legacy fields above.
    event.update(canonical_features)
    return event


@app.get("/")
def root():
    return jsonify(
        {
            "service": "ai-driven-ids-verification-layer",
            "status": "ok",
            "endpoints": [
                "/health",
                "/api/v1/ml/metadata",
                "/api/v1/ml/verifier/metadata",
                "/api/v1/analyze",
                "/api/v1/analyze/csv",
                "/api/v1/datasets",
                "/api/v1/datasets/upload",
                "/api/v1/datasets/<dataset_id>/analyze",
                "/api/v1/reports",
                "/api/v1/reports/export",
            ],
        }
    )


@app.get("/health")
def health():
    predictor_instance = get_predictor()
    verifier_instance = get_verifier()
    return jsonify(
        {
            "status": "ok",
            "model_available": predictor_instance.available,
            "model_version": predictor_instance.model_version,
            "verifier_available": verifier_instance.available,
            "verifier_model_version": verifier_instance.model_version,
        }
    )


@app.get("/api/v1/ml/metadata")
def ml_metadata():
    predictor_instance = get_predictor()
    verifier_instance = get_verifier()
    return jsonify(
        {
            "model_available": predictor_instance.available,
            "model_version": predictor_instance.model_version,
            "model_info": predictor_instance.model_info,
            "metrics": predictor_instance.metrics,
            "verifier": {
                "model_available": verifier_instance.available,
                "model_version": verifier_instance.model_version,
                "model_info": verifier_instance.metadata,
                "metrics": verifier_instance.metrics,
            },
            "datasets": [
                "CIC-IDS2017",
                "CIC-UNSW-NB15 (Augmented)",
            ],
        }
    )


@app.get("/api/v1/ml/verifier/metadata")
def verifier_metadata():
    verifier_instance = get_verifier()
    return jsonify(
        {
            "model_available": verifier_instance.available,
            "model_version": verifier_instance.model_version,
            "model_info": verifier_instance.metadata,
            "metrics": verifier_instance.metrics,
        }
    )


@app.post("/api/v1/reports/<int:report_id>/feedback")
def report_feedback(report_id: int):
    """Record analyst verdict for a stored report.

    Request body:
      { "verdict": "confirmed_threat" | "confirmed_benign" | "false_positive" | "false_negative",
        "notes": "<optional free text>" }

    Response (200):
      { "status": "ok", "report_id": int, "verdict": str }

    Response (400): unknown verdict value.
    Response (404): report_id not found.

    Stores verdict + notes + reviewed_at timestamp in the reports table.
    This endpoint is the primary data source for online fine-tuning via
    POST /api/v1/ml/verifier/fine-tune.

    # Thesis Table 10 amendment — add to Section 3.5
    """
    body = request.get_json(silent=True) or {}
    verdict = body.get("verdict", "")
    if verdict not in ANALYST_VERDICTS:
        return jsonify({"error": f"Unknown verdict. Allowed: {list(ANALYST_VERDICTS)}"}), 400
    found = add_analyst_feedback(
        report_id=report_id,
        verdict=verdict,
        notes=body.get("notes"),
    )
    if not found:
        return jsonify({"error": f"Report {report_id} not found"}), 404
    return jsonify({"status": "ok", "report_id": report_id, "verdict": verdict}), 200


@app.get("/api/v1/ml/verifier/feedback-stats")
def verifier_feedback_stats():
    """Return analyst feedback statistics used by the online-learning UI.

    Response: { "total_feedback": int }

    total_feedback — total analyst verdicts stored in the reports table.
    Used by the Settings screen to show how many samples are available for fine-tuning.

    # Thesis Table 10 amendment — add to Section 3.5
    """
    conn = get_conn()
    total = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE analyst_verdict IS NOT NULL"
    ).fetchone()[0]
    conn.close()
    return jsonify({"total_feedback": int(total)})


@app.post("/api/v1/ml/verifier/fine-tune")
def verifier_fine_tune():
    """Fine-tune the verifier ensemble on recent confirmed reports from reports.db.

    Optional body: { "hours": int, "min_samples": int, "epochs": int, "learning_rate": float }
    Defaults: hours=24, min_samples=50, epochs=3, learning_rate=1e-4.

    Response on success:
      { "status": "ok", "feedback_samples": int, "replay_samples": int,
        "total_training_samples": int, "epochs": int, "drift": { ... } }
    Response when skipped:
      { "status": "skipped", "reason": "too_few_feedback_samples" | "no_artifact", ... }

    Reloads the verifier in-process after a successful fine-tune so new weights
    are used immediately without a restart.

    # Thesis Table 10 amendment — add to Section 3.5
    """
    from verification.online_learning import fine_tune
    body = request.get_json(silent=True) or {}
    result = fine_tune(
        hours=int(body.get("hours", 24)),
        min_samples=int(body.get("min_samples", 50)),
        epochs=int(body.get("epochs", 3)),
        learning_rate=float(body.get("learning_rate", 1e-4)),
    )
    # Reload the verifier so the updated weights are used immediately.
    global verifier
    verifier = None
    return jsonify(result), 200


@app.post("/api/v1/analyze")
def analyze():
    payload = _json_payload()
    event_payload = payload.get("event") or payload
    response = _analysis_response(event_payload)
    return jsonify(response), 200


@app.post("/api/v1/analyze/csv")
def analyze_csv():
    if "file" not in request.files:
        return jsonify({"error": "No CSV file provided"}), 400

    file_storage = request.files["file"]
    limit = int(request.form.get("limit", 50))
    reader = _csv_dict_reader_from_upload(file_storage)

    results = []
    for index, row in enumerate(reader, start=1):
        if index > limit:
            break
        event = _event_from_csv_row(index, row, file_storage.filename or "uploaded.csv")
        results.append(_analysis_response(event))

    return jsonify(
        {
            "filename": file_storage.filename,
            "processed": len(results),
            "limit": limit,
            "results": results,
        }
    )


@app.get("/api/v1/datasets")
def api_list_datasets():
    return jsonify(list_datasets())


@app.post("/api/v1/datasets/upload")
def api_upload_dataset():
    if "file" not in request.files:
        return jsonify({"error": "No file field 'file'"}), 400
    try:
        meta = save_uploaded_dataset(request.files["file"])
        return jsonify(meta), 201
    except Exception as exception:
        return jsonify({"error": str(exception)}), 400


@app.post("/api/v1/datasets/<dataset_id>/analyze")
def analyze_dataset(dataset_id: str):
    limit = int(request.args.get("limit", 100))
    datasets = list_datasets()
    meta = next((item for item in datasets if item.get("dataset_id") == dataset_id), None)
    if not meta:
        return jsonify({"error": "Dataset not found"}), 404

    file_path = Path(__file__).resolve().parent / "uploads" / meta["stored_name"]
    if not file_path.exists():
        return jsonify({"error": f"File not found on server: {meta['stored_name']}"}), 404

    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        results = []
        for index, row in enumerate(reader, start=1):
            if index > limit:
                break
            event = _event_from_csv_row(index, row, meta["filename"])
            results.append(_analysis_response(event))

    return jsonify(
        {
            "dataset_id": dataset_id,
            "filename": meta["filename"],
            "processed": len(results),
            "limit": limit,
            "results": results[:10],
        }
    )


@app.get("/api/v1/reports")
def reports_list():
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    where = []
    params = []
    if date_from:
        where.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("created_at <= ?")
        params.append(date_to)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    conn = get_conn()
    summary = conn.execute(
        f"""
        SELECT
          COUNT(*) as total,
          COALESCE(SUM(CASE WHEN COALESCE(final_status, decision_status, label) = 'Benign' THEN 1 ELSE 0 END), 0) as benign,
          COALESCE(SUM(CASE WHEN COALESCE(final_status, decision_status, label) = 'Verified Threat' THEN 1 ELSE 0 END), 0) as verified_threat,
          COALESCE(SUM(CASE WHEN COALESCE(final_status, decision_status, label) = 'Suspicious' THEN 1 ELSE 0 END), 0) as suspicious,
          COALESCE(SUM(CASE WHEN COALESCE(final_status, decision_status, label) != 'Benign' THEN 1 ELSE 0 END), 0) as non_normal
        FROM reports {where_sql}
        """,
        params,
    ).fetchone()

    rows = conn.execute(
        f"""
        SELECT * FROM reports
        {where_sql}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset],
    ).fetchall()
    conn.close()

    items = []
    for row in rows:
        item = dict(row)
        for key in (
            "traffic_context",
            "raw_input",
            "detector_output",
            "verification_output",
            "final_decision",
            "event_snapshot",
        ):
            if item.get(key):
                try:
                    item[key] = json.loads(item[key])
                except Exception:
                    pass
        items.append(item)

    return jsonify(
        {
            "summary": dict(summary),
            "items": items,
            "limit": limit,
            "offset": offset,
        }
    )


@app.get("/api/v1/reports/<int:report_id>")
def get_report(report_id: int):
    item = get_report_by_id(report_id)
    if item is None:
        return jsonify({"error": "report not found", "report_id": report_id}), 404
    return jsonify(item), 200


@app.get("/api/v1/reports/export")
def export_reports():
    fmt = request.args.get("format", "csv").lower()
    date_from = request.args.get("from")
    date_to = request.args.get("to")

    where = []
    params = []
    if date_from:
        where.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("created_at <= ?")
        params.append(date_to)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_conn()
    rows = conn.execute(
        f"SELECT * FROM reports {where_sql} ORDER BY created_at DESC",
        params,
    ).fetchall()
    conn.close()

    data = [dict(row) for row in rows]
    if fmt == "json":
        body = json.dumps(data, ensure_ascii=False)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=reports.json"},
        )

    output = io.StringIO()
    fieldnames = data[0].keys() if data else ["created_at", "label", "confidence", "decision_status"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in data:
        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=reports.csv"},
    )


# ---------------------------------------------------------------------------
# Real-time endpoints
# ---------------------------------------------------------------------------

@app.post("/api/realtime/start")
def realtime_start():
    with _monitor_lock:
        monitor = _get_monitor()
        if monitor is not None and monitor.is_running:
            return jsonify({"error": "Monitor is already running. Stop it first."}), 409

        body = request.get_json(silent=True) or {}
        source = body.get("source", "synthetic")
        interface = _normalize_interface(body.get("interface", "eth0"))
        batch_size = int(body.get("batch_size", 32))
        rate_limit = float(body.get("rate_limit", 0.05))
        attack_ratio = float(body.get("attack_ratio", 0.3))
        promiscuous = _safe_bool(body.get("promiscuous", False))

        if source not in ("pyshark", "scapy", "synthetic"):
            return jsonify({"error": f"Unknown source '{source}'. Choose: pyshark, scapy, synthetic."}), 400

        try:
            from realtime.pipeline import StreamMonitor
            m = StreamMonitor(
                source=source,
                interface=interface,
                rate_limit=rate_limit,
                attack_ratio=attack_ratio,
                batch_size=batch_size,
                console_output=True,
                promiscuous=promiscuous,
            )
            _set_monitor(m)
            t = threading.Thread(target=m.start, kwargs={"blocking": True}, daemon=True)
            t.start()
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "started", "source": source, "batch_size": batch_size}), 200


@app.post("/api/realtime/stop")
def realtime_stop():
    with _monitor_lock:
        monitor = _get_monitor()
        if monitor is None or not monitor.is_running:
            return jsonify({"error": "No monitor is currently running."}), 409
        monitor.stop()
        _set_monitor(None)
    return jsonify({"status": "stopped"}), 200


@app.get("/api/realtime/status")
def realtime_status():
    monitor = _get_monitor()
    if monitor is None:
        return jsonify({"running": False, "buffer_size": 0}), 200
    return jsonify(monitor.status()), 200


@app.get("/api/realtime/debug")
def realtime_debug():
    """Diagnostic endpoint — returns full monitor state including counters and errors."""
    monitor = _get_monitor()
    if monitor is None:
        return jsonify({"monitor": None, "running": False}), 200
    return jsonify(monitor.status()), 200


@app.get("/api/realtime/interfaces")
def realtime_interfaces():
    """List all available network interfaces with their descriptions."""
    result: dict = {"scapy": [], "pyshark": [], "errors": {}}

    # --- scapy (cross-platform) ---
    try:
        if sys.platform == "win32":
            from scapy.arch.windows import get_windows_if_list  # type: ignore
            for iface in get_windows_if_list():
                name: str = iface.get("name", "")
                guid = name.replace(r"\Device\NPF_", "").strip("{}")
                result["scapy"].append({
                    "guid": guid,
                    "name": name,
                    "description": iface.get("description", ""),
                    "ips": iface.get("ips", []),
                })
        else:
            from scapy.all import get_if_list, get_if_addr  # type: ignore
            for iface_name in get_if_list():
                try:
                    ip = get_if_addr(iface_name)
                except Exception:
                    ip = ""
                result["scapy"].append({
                    "guid": iface_name,
                    "name": iface_name,
                    "description": iface_name,
                    "ips": [ip] if ip and ip != "0.0.0.0" else [],
                })
    except Exception as exc:
        result["errors"]["scapy"] = str(exc)

    # --- pyshark / tshark ---
    try:
        import subprocess
        import shutil
        # Try to find tshark: standard path, then macOS Homebrew, then PATH
        tshark_path = None
        for candidate in ["tshark", "/opt/homebrew/bin/tshark", "/usr/local/bin/tshark"]:
            if shutil.which(candidate) or (candidate != "tshark" and os.path.exists(candidate)):
                tshark_path = candidate
                break

        if tshark_path is None:
            tshark_path = "tshark"  # fallback, will fail but with clear error

        proc = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"tshark failed: {proc.stderr}")

        lines = proc.stdout.strip().splitlines()
        for line in lines:
            # format: "1. \Device\NPF_{GUID} (Description)"
            parts = line.split(". ", 1)
            if len(parts) == 2:
                rest = parts[1]
                desc_start = rest.find("(")
                iface_name = rest[:desc_start].strip() if desc_start != -1 else rest.strip()
                desc = rest[desc_start + 1:rest.rfind(")")] if desc_start != -1 else ""
                result["pyshark"].append({"name": iface_name, "description": desc})
    except Exception as exc:
        result["errors"]["pyshark"] = str(exc)

    return jsonify(result), 200


@app.get("/api/realtime/results")
def realtime_results():
    monitor = _get_monitor()
    if monitor is None:
        return jsonify({"results": [], "running": False}), 200
    items = monitor.drain_results()
    return jsonify({
        "results": [r.to_sse_dict() for r in items],
        "running": monitor.is_running,
    }), 200


@app.get("/api/realtime/stream")
def realtime_stream():
    def _generate():
        last_hb = time.time()
        while True:
            m = _get_monitor()
            if m is not None:
                for result in m.drain_results():
                    payload = json.dumps(result.to_sse_dict())
                    yield f"data: {payload}\n\n"
            now = time.time()
            if now - last_hb >= 15:
                yield ": heartbeat\n\n"
                last_hb = now
            time.sleep(0.2)

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or __name__ == "__main__":
        predictor = MLPredictor()
        verifier = SecureDecisionVerificationService(predictor)
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=True)

