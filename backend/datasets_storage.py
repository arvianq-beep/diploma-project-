import os
import json
import uuid
import datetime
from pathlib import Path
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
META_PATH = BASE_DIR / "datasets.json"

ALLOWED_EXT = {"csv"}
MAX_MB = 200

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _load_meta():
    if not META_PATH.exists():
        return []
    return json.loads(META_PATH.read_text(encoding="utf-8"))


def _save_meta(items):
    META_PATH.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def list_datasets():
    return _load_meta()


def save_uploaded_dataset(file_storage):
    if file_storage is None:
        raise ValueError("No file provided")

    filename = file_storage.filename or ""
    if filename.strip() == "":
        raise ValueError("Empty filename")

    if "." not in filename:
        raise ValueError("Only .csv allowed")

    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXT:
        raise ValueError("Only .csv allowed")

    # size check
    file_storage.stream.seek(0, os.SEEK_END)
    size_bytes = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size_bytes > MAX_MB * 1024 * 1024:
        raise ValueError(f"File too large (max {MAX_MB}MB)")

    dataset_id = str(uuid.uuid4())
    safe_name = secure_filename(filename)
    stored_name = f"{dataset_id}_{safe_name}"
    save_path = UPLOAD_DIR / stored_name
    file_storage.save(str(save_path))

    meta = {
        "dataset_id": dataset_id,
        "filename": safe_name,
        "stored_name": stored_name,
        "size_bytes": size_bytes,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
    }

    items = _load_meta()
    items.insert(0, meta)
    _save_meta(items)

    return meta