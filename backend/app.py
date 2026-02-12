import os
import uuid
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

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

if __name__ == "__main__":
    print(app.url_map)  # временно для проверки маршрутов
    app.run(host="127.0.0.1", port=5001, debug=True)
