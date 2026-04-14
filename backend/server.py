from __future__ import annotations

import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request
from flask_cors import CORS

from datasets_storage import list_datasets, save_uploaded_dataset
from ml.inference import MLPredictor
from ml.schema import CIC_COLUMN_ALIASES
from storage import get_conn, init_db, insert_report


app = Flask(__name__)
CORS(app)

init_db()

predictor: MLPredictor | None = None


def get_predictor() -> MLPredictor:
    global predictor
    if predictor is None:
        predictor = MLPredictor()
    return predictor


def _json_payload():
    return request.get_json(silent=True) or {}


def _normalize_event(event_payload: dict, fallback_id: str | None = None) -> dict:
    event_id = str(event_payload.get("id") or fallback_id or uuid.uuid4())
    captured_raw = event_payload.get("captured_at") or event_payload.get("timestamp")
    captured_at = captured_raw or datetime.now(timezone.utc).isoformat()

    return {
        "id": event_id,
        "title": str(event_payload.get("title", f"Imported event {event_id}")),
        "description": str(event_payload.get("description", "Network event submitted for ML analysis.")),
        "source_ip": str(event_payload.get("source_ip", "0.0.0.0")),
        "destination_ip": str(event_payload.get("destination_ip", "0.0.0.0")),
        "source_port": int(float(event_payload.get("source_port", 0) or 0)),
        "destination_port": int(float(event_payload.get("destination_port", 0) or 0)),
        "protocol": str(event_payload.get("protocol", "UNKNOWN")),
        "bytes_transferred_kb": float(event_payload.get("bytes_transferred_kb", 0.0) or 0.0),
        "duration_seconds": float(event_payload.get("duration_seconds", 0.0) or 0.0),
        "packets_per_second": float(event_payload.get("packets_per_second", 0.0) or 0.0),
        "failed_logins": int(float(event_payload.get("failed_logins", 0) or 0)),
        "anomaly_score": float(event_payload.get("anomaly_score", 0.0) or 0.0),
        "context_risk_score": float(event_payload.get("context_risk_score", 0.0) or 0.0),
        "known_bad_source": bool(event_payload.get("known_bad_source", False)),
        "off_hours_activity": bool(event_payload.get("off_hours_activity", False)),
        "repeated_attempts": bool(event_payload.get("repeated_attempts", False)),
        "sample_source": str(event_payload.get("sample_source", "Backend API")),
        "captured_at": captured_at,
        "tags": event_payload.get("tags", []),
    }


def _analysis_response(event_payload: dict) -> dict:
    predictor_instance = get_predictor()
    normalized_event = _normalize_event(event_payload)
    output = predictor_instance.predict_from_event(normalized_event)

    response = {
        "event_id": normalized_event["id"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event": normalized_event,
        "prediction": {
            "label": output.label,
            "confidence": output.confidence,
            "stability_score": output.stability_score,
            "model_version": output.model_version,
            "reasoning": output.reasoning,
            "alternative_hypothesis": output.alternative_hypothesis,
            "triggered_indicators": output.triggered_indicators,
            "feature_snapshot": output.feature_snapshot,
            "model_available": predictor_instance.available,
        },
    }

    insert_report(
        label=output.label,
        confidence=output.confidence,
        decision_status="Raw AI prediction",
        decision_reason=output.reasoning,
        traffic_context={
            "event": normalized_event,
            "prediction": response["prediction"],
        },
        raw_input=event_payload,
    )

    return response


def _csv_dict_reader_from_upload(file_storage):
    body = file_storage.stream.read().decode("utf-8", errors="ignore")
    file_storage.stream.seek(0)
    return csv.DictReader(io.StringIO(body))


def _extract_canonical_features_from_row(row: dict[str, str]) -> dict:
    """Try to read all 77 canonical features from a CSV dict row using CIC-style aliases.

    Returns a dict of {canonical_name: float} for every feature that could be
    resolved.  Features not found in the row are omitted (they will default to
    0.0inside MLPredictor._normalize_features).
    """
    # Build a case-insensitive index of the row's keys for fast alias lookup.
    row_index: dict[str, str] = {k.strip().lower(): k for k in row}
    result: dict[str, float] = {}
    for feature, aliases in CIC_COLUMN_ALIASES.items():
        for alias in aliases:
            raw_key = row_index.get(alias.strip().lower())
            if raw_key is not None:
                raw_val = str(row[raw_key]).strip()
                if raw_val not in {"", "nan", "inf", "-inf"}:
                    try:
                        result[feature] = float(raw_val)
                    except ValueError:
                        pass
                break
    return result


def _event_from_csv_row(row_index: int, row: dict[str, str], filename: str) -> dict:
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

    def normalize_protocol(value: str) -> str:
        normalized = str(value).strip()
        return {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(
            normalized, normalized.upper() if normalized else "UNKNOWN"
        )

    # --- identity / metadata fields (unchanged) ---
    source_ip = read("source_ip", "srcip", "Src IP", "Source IP", default="0.0.0.0")
    destination_ip = read("destination_ip", "dstip", "Dst IP", "Destination IP", default="0.0.0.0")
    protocol = normalize_protocol(read("protocol", "proto", "Protocol", default="UNKNOWN"))
    label = read("Label", "label", "attack_cat", default="")

    # --- attempt to extract all 77 canonical features from the row ---
    canonical = _extract_canonical_features_from_row(row)

    # Derive legacy fields as a fallback for non-CIC CSVs that lack canonical names.
    destination_port = read_int("destination_port", "dsport", "Destination Port", "Dst Port", default=0)
    source_port = read_int("source_port", "sport", "Src Port", "Source Port", default=0)
    duration = read_float("duration_seconds", "duration", "dur", "Flow Duration", default=1.0)
    if duration > 10_000:
        # CIC raw files store duration in microseconds; convert here when
        # the canonical extractor above has NOT already done so.
        if "flow_duration" not in canonical:
            duration = duration / 1_000_000.0
    flow_bytes_per_second = read_float(
        "Flow Bytes/s", "Flow Byts/s", "bytes_per_second", "flow_bytes_per_second", default=0.0
    )
    forward_packets = read_float("forward_packets", "spkts", "Tot Fwd Pkts", "Total Fwd Packets", default=0.0)
    backward_packets = read_float("backward_packets", "dpkts", "Tot Bwd Pkts", "Total Backward Packets", default=0.0)
    packets_per_second = read_float("packets_per_second", "Flow Packets/s", "Flow Pkts/s", "rate", default=0.0)
    if packets_per_second == 0.0 and duration > 0:
        total_packets = forward_packets + backward_packets
        packets_per_second = total_packets / duration if duration else 0.0
    bytes_kb = read_float(
        "bytes_transferred_kb", "bytes", "flow_bytes", "sbytes",
        "Total Length of Fwd Packets", default=0.0,
    ) / 1024.0
    if bytes_kb == 0.0 and flow_bytes_per_second > 0 and duration > 0:
        bytes_kb = (flow_bytes_per_second * duration) / 1024.0

    event: dict = {
        "id": f"csv-{row_index}",
        "title": f"CSV Event {row_index}",
        "description": (
            f"Imported from {filename}"
            if not label
            else f"Imported from {filename} with dataset label {label}"
        ),
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
        "known_bad_source": (
            str(read("known_bad_source", default="false")).lower() == "true"
            or source_ip.startswith(("185.", "45."))
        ),
        "off_hours_activity": str(read("off_hours_activity", default="false")).lower() == "true",
        "repeated_attempts": (
            str(read("repeated_attempts", default="false")).lower() == "true"
            or packets_per_second > 400
            or destination_port == 22
        ),
        "sample_source": f"CSV Import: {filename}",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "tags": ["csv-import", *([f"dataset-label:{label}"] if label else [])],
    }

    # Merge extracted canonical features into the event dict.  When present,
    # MLPredictor.predict_from_event() will detect them and use the primary
    # 77-feature inference path instead of the legacy compat path.
    if canonical:
        event.update(canonical)

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
    return jsonify(
        {
            "status": "ok",
            "model_available": predictor_instance.available,
            "model_version": predictor_instance.model_version,
        }
    )


@app.get("/api/v1/ml/metadata")
def ml_metadata():
    predictor_instance = get_predictor()
    return jsonify(
        {
            "model_available": predictor_instance.available,
            "model_version": predictor_instance.model_version,
            "model_info": predictor_instance.model_info,
            "metrics": predictor_instance.metrics,
            "datasets": [
                "CIC-IDS2017",
                "CIC-UNSW-NB15 (Augmented)",
            ],
        }
    )


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
          COALESCE(SUM(CASE WHEN label = 'Benign' THEN 1 ELSE 0 END), 0) as normal,
          COALESCE(SUM(CASE WHEN label != 'Benign' THEN 1 ELSE 0 END), 0) as non_normal,
          0 as verified_threat,
          0 as suspicious
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
        for key in ("traffic_context", "raw_input"):
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


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or __name__ == "__main__":
        predictor = MLPredictor()
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=True)
