from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import uuid
from datetime import datetime, timezone
import json
import csv
import io
import os

from secure_ai import SecureDecisionModel
from storage import init_db, insert_report, get_conn

app = Flask(__name__)
CORS(app)

# Инициализация БД безопасна даже при debug reloader (таблица создаётся, если нет)
init_db()

# В debug режиме Flask запускает код 2 раза (reloader).
# Чтобы модель не инициализировалась дважды, создаём её только в основном процессе.
model = None
if (not app.debug) or (os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
    model = SecureDecisionModel()
else:
    # в первом процессе (наблюдателе) модель не нужна
    model = SecureDecisionModel()

BENIGN_LABELS = {"BENIGN", "Benign", "benign", "Normal", "normal", "Normal Traffic", "normal traffic"}

def _run_model(_features):
    """
    Сейчас SecureDecisionModel.analyze_packet() сам генерирует пакет (как у тебя).
    Позже можно использовать _features/входной JSON, если захочешь принимать реальные признаки.
    """
    out = model.analyze_packet()

    label = str(out.get("threat_type", "Unknown"))
    confidence = float(out.get("ai_confidence", 0.0))

    is_threat = bool(out.get("is_threat", False))
    is_verified = bool(out.get("is_verified", True))
    details = str(out.get("verification_details", ""))

    verification = {
        "passed": is_verified,
        "checks": [
            {
                "name": "model_verification",
                "passed": is_verified,
                "details": details,
            },
            {
                "name": "traffic_context",
                "passed": True,
                "details": f"src_ip={out.get('source_ip')} proto={out.get('protocol')} ts={out.get('timestamp')}",
            },
        ],
    }

    traffic_context = {
        "source_ip": out.get("source_ip"),
        "destination_ip": out.get("destination_ip"),
        "protocol": out.get("protocol"),
        "timestamp": out.get("timestamp"),
    }

    return label, confidence, verification, is_threat, traffic_context, out


@app.get("/")
def root():
    return jsonify({
        "service": "secure-decision-making-ids",
        "status": "ok",
        "endpoints": ["/health", "/api/v1/analyze", "/api/v1/reports", "/api/v1/reports/export"]
    })

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/v1/analyze")
def analyze():
    request_json = request.get_json(silent=True) or {}

    label, confidence, verification, is_threat, traffic_context, raw_out = _run_model(
        request_json.get("features")
    )

    # Secure decision-making logic (detection -> verification -> operational status)
    is_benign = (label in BENIGN_LABELS) and (not is_threat)

    if is_benign or (not is_threat):
        decision_status = "Normal (No Threat)"
        action = "Log for monitoring; no escalation"
        # benign всегда считаем passed
        verification = {"passed": True, "checks": verification.get("checks", [])}
    else:
        if verification.get("passed", True):
            decision_status = "Verified Threat"
            action = "Escalate as confirmed alert; prioritize response; include in reporting"
        else:
            decision_status = "Suspicious (Verification Failed)"
            action = "Flag for analyst review; retain verification details; monitor for corroboration"

    resp = {
        "event_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "prediction": {"label": label, "confidence": confidence},
        "verification": verification,
        "decision_status": decision_status,
        "recommended_action": action,
        "traffic_context": traffic_context,
    }

    # Сохранение для Reports (SQLite)
    insert_report(
        label=label,
        confidence=confidence,
        decision_status=decision_status,
        decision_reason=action,
        traffic_context={
            "traffic_context": traffic_context,
            "verification": verification,
            "raw_out": raw_out,  # если хочешь, можно убрать
        },
        raw_input=request_json
    )

    return jsonify(resp), 200


@app.get("/api/v1/reports")
def reports_list():
    date_from = request.args.get("from")   # ISO 8601
    date_to = request.args.get("to")       # ISO 8601
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

    # summary: считаем нормальные по 'Normal%'
    summary = conn.execute(
        f"""
        SELECT
          COUNT(*) as total,
          COALESCE(SUM(CASE WHEN decision_status LIKE 'Normal%' THEN 1 ELSE 0 END), 0) as normal,
          COALESCE(SUM(CASE WHEN decision_status = 'Verified Threat' THEN 1 ELSE 0 END), 0) as verified_threat,
          COALESCE(SUM(CASE WHEN decision_status LIKE 'Suspicious%' THEN 1 ELSE 0 END), 0) as suspicious,
          COALESCE(SUM(CASE WHEN decision_status NOT LIKE 'Normal%' THEN 1 ELSE 0 END), 0) as non_normal
        FROM reports {where_sql}
        """,
        params
    ).fetchone()

    rows = conn.execute(
        f"""
        SELECT * FROM reports
        {where_sql}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset]
    ).fetchall()

    conn.close()

    items = []
    for r in rows:
        d = dict(r)
        # опционально: декодируем JSON поля, чтобы Flutter мог сразу использовать
        for key in ("traffic_context", "raw_input"):
            if d.get(key):
                try:
                    d[key] = json.loads(d[key])
                except Exception:
                    pass
        items.append(d)

    return jsonify({
        "summary": dict(summary),
        "items": items,
        "limit": limit,
        "offset": offset
    })


@app.get("/api/v1/reports/export")
def export_reports():
    fmt = request.args.get("format", "csv").lower()
    date_from = request.args.get("from")
    date_to = request.args.get("to")

    where = []
    params = []
    if date_from:
        where.append("created_at >= ?"); params.append(date_from)
    if date_to:
        where.append("created_at <= ?"); params.append(date_to)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_conn()
    rows = conn.execute(
        f"SELECT * FROM reports {where_sql} ORDER BY created_at DESC",
        params
    ).fetchall()
    conn.close()

    data = [dict(r) for r in rows]

    if fmt == "json":
        body = json.dumps(data, ensure_ascii=False)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=reports.json"}
        )

    # CSV
    output = io.StringIO()
    fieldnames = data[0].keys() if data else ["created_at", "label", "confidence", "decision_status"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in data:
        writer.writerow(r)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=reports.csv"}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=True)
