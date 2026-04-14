import json
import os
import threading
import time
import uuid

import pandas as pd
from flask import Flask, Response, request, jsonify, stream_with_context
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------------
# Real-time monitor — a single global instance shared across requests.
# Created lazily on the first POST /api/realtime/start.
# ---------------------------------------------------------------------------
_monitor_lock = threading.Lock()
_monitor = None  # type: ignore[assignment]


def _get_monitor():
    return _monitor


def _set_monitor(m):
    global _monitor
    _monitor = m

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB
ALLOWED_EXTENSIONS = {"csv"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.get("/api/datasets")
def list_datasets():
    items = []
    for name in os.listdir(UPLOAD_DIR):
        if name.lower().endswith(".csv"):
            items.append({"stored_name": name})
    return jsonify({"datasets": sorted(items, key=lambda x: x["stored_name"])}), 200

@app.get("/api/datasets/<dataset_id>")
def get_dataset_info(dataset_id):
    matches = [f for f in os.listdir(UPLOAD_DIR) if f.startswith(dataset_id + "_")]
    if not matches:
        return jsonify({"error": "Dataset not found"}), 404

    stored_name = matches[0]
    filename = stored_name.split("_", 1)[1]

    return jsonify({
        "dataset_id": dataset_id,
        "stored_name": stored_name,
        "filename": filename
    }), 200



@app.get("/api/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.post("/api/datasets")
def upload_dataset():
    if "file" not in request.files:
        return jsonify({"error": "No file field 'file' in form-data"}), 400

    f = request.files["file"]

    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(f.filename):
        return jsonify({"error": "Only .csv is allowed"}), 400

    dataset_id = str(uuid.uuid4())
    safe_name = secure_filename(f.filename)
    saved_path = os.path.join(UPLOAD_DIR, f"{dataset_id}_{safe_name}")
    f.save(saved_path)

    # Preview: читаем только первые строки, чтобы не грузить весь файл
    try:
        preview_df = pd.read_csv(saved_path, nrows=2000)
        columns = list(preview_df.columns)
    except Exception as e:
        return jsonify({"error": f"Saved but cannot read CSV: {str(e)}"}), 400

    return jsonify({
        "dataset_id": dataset_id,
        "filename": safe_name,
        "columns": columns,
        "preview_rows": len(preview_df)
    }), 201

# ---------------------------------------------------------------------------
# Real-time endpoints
# ---------------------------------------------------------------------------

@app.post("/api/realtime/start")
def realtime_start():
    """Start real-time traffic monitoring.

    Body (JSON, all optional):
        source        — "synthetic" | "csv" | "pyshark" | "scapy"  (default: "synthetic")
        interface     — network interface for pyshark/scapy          (default: "eth0")
        csv_path      — path to CSV for source="csv"
        batch_size    — flows per inference batch                     (default: 32)
        rate_limit    — seconds between packets for csv/synthetic     (default: 0.05)
        attack_ratio  — synthetic attack fraction 0–1                 (default: 0.3)
    """
    with _monitor_lock:
        monitor = _get_monitor()
        if monitor is not None and monitor.is_running:
            return jsonify({"error": "Monitor is already running. Stop it first."}), 409

        body = request.get_json(silent=True) or {}
        source = body.get("source", "synthetic")
        interface = body.get("interface", "eth0")
        csv_path = body.get("csv_path")
        batch_size = int(body.get("batch_size", 32))
        rate_limit = float(body.get("rate_limit", 0.05))
        attack_ratio = float(body.get("attack_ratio", 0.3))

        # Validate csv_path exists when source="csv"
        if source == "csv":
            if not csv_path:
                return jsonify({"error": "csv_path is required when source='csv'"}), 400
            if not os.path.isfile(csv_path):
                return jsonify({"error": f"csv_path not found: {csv_path}"}), 400

        try:
            from realtime.pipeline import StreamMonitor
            m = StreamMonitor(
                source=source,
                interface=interface,
                csv_path=csv_path,
                rate_limit=rate_limit,
                attack_ratio=attack_ratio,
                batch_size=batch_size,
                console_output=True,
            )
            _set_monitor(m)
            # Start in non-blocking mode so the HTTP request returns immediately
            t = threading.Thread(target=m.start, kwargs={"blocking": True}, daemon=True)
            t.start()
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    return jsonify({
        "status": "started",
        "source": source,
        "batch_size": batch_size,
    }), 200


@app.post("/api/realtime/stop")
def realtime_stop():
    """Stop the running real-time monitor."""
    with _monitor_lock:
        monitor = _get_monitor()
        if monitor is None or not monitor.is_running:
            return jsonify({"error": "No monitor is currently running."}), 409
        monitor.stop()
        _set_monitor(None)
    return jsonify({"status": "stopped"}), 200


@app.get("/api/realtime/status")
def realtime_status():
    """Return current monitor status and buffer size."""
    monitor = _get_monitor()
    if monitor is None:
        return jsonify({"running": False, "buffer_size": 0}), 200
    return jsonify(monitor.status()), 200


@app.get("/api/realtime/results")
def realtime_results():
    """Return and clear all buffered StreamResult objects as JSON.

    Used by Flutter for periodic polling (every ~1 s).
    Returns:
        {"results": [...], "running": bool}
    """
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
    """Server-Sent Events stream of StreamResult objects.

    Each SSE event has the form:
        data: <JSON>\\n\\n

    The client should connect with:
        const es = new EventSource('/api/realtime/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));

    The stream sends a heartbeat comment every 15 s to keep the connection
    alive through proxies that close idle connections.
    """
    def _generate():
        last_hb = time.time()
        while True:
            monitor = _get_monitor()
            if monitor is not None:
                for result in monitor.drain_results():
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
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    print(app.url_map)  # временно для проверки маршрутов
    app.run(host="127.0.0.1", port=5001, debug=True, threaded=True)
