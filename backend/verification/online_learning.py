from __future__ import annotations

"""Online fine-tuning of the verifier ensemble on analyst-confirmed reports.

Flow:
  1. Analyst reviews SUSPICIOUS / VERIFIED_THREAT events via the API.
  2. They POST /api/v1/reports/{id}/feedback with a verdict.
  3. This script reads those confirmed samples, detects feature drift,
     and fine-tunes each ensemble member if enough feedback has accumulated.

Usage (from backend/):
    python -m verification.online_learning [--min-samples 50] [--hours 168]

Drift detection uses Population Stability Index (PSI):
  PSI < 0.10  — stable, fine-tune only if enough new samples
  PSI 0.10-0.25 — moderate drift, fine-tune recommended
  PSI > 0.25  — major drift, schedule full retraining
"""

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from .model import load_artifacts, save_artifacts
from .schema import VERIFIER_FEATURE_NAMES

_DB_PATH = Path(__file__).resolve().parent.parent / "reports.db"

# Fine-tune hyper-parameters kept deliberately small to avoid catastrophic forgetting.
_FT_EPOCHS = 3
_FT_LR = 5e-5       # much smaller than initial training (1.5e-3) — conservative update
_FT_BATCH = 32
_REPLAY_FRACTION = 0.30   # fraction of background samples mixed in to prevent forgetting

# PSI thresholds
_PSI_STABLE = 0.10
_PSI_MAJOR_DRIFT = 0.25


# ── label mapping ─────────────────────────────────────────────────────────────

# confirmed_threat / confirmed_benign → verifier should say "trust" (label=1)
# false_positive / false_negative     → verifier should say "don't trust" (label=0)
_VERDICT_LABEL: dict[str, float] = {
    "confirmed_threat": 1.0,
    "confirmed_benign": 1.0,
    "false_positive": 0.0,
    "false_negative": 0.0,
}


# ── data loading ──────────────────────────────────────────────────────────────

def _load_feedback_samples(
    db_path: Path,
    hours: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Load feature vectors and verifier labels from analyst-confirmed reports."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT final_decision, analyst_verdict
        FROM reports
        WHERE analyst_verdict IS NOT NULL
          AND analyst_reviewed_at >= datetime('now', ?)
        ORDER BY analyst_reviewed_at DESC
        """,
        (f"-{hours} hours",),
    ).fetchall()
    conn.close()

    vectors: list[list[float]] = []
    labels: list[float] = []

    for row in rows:
        verdict = row["analyst_verdict"]
        if verdict not in _VERDICT_LABEL:
            continue
        try:
            fd = json.loads(row["final_decision"] or "{}")
            vi: dict[str, float] = fd.get("feature_snapshot", {}).get("verifier_input", {})
            if len(vi) < len(VERIFIER_FEATURE_NAMES):
                continue
            vectors.append([float(vi.get(n, 0.0)) for n in VERIFIER_FEATURE_NAMES])
            labels.append(_VERDICT_LABEL[verdict])
        except Exception:
            continue

    if not vectors:
        return np.empty((0, len(VERIFIER_FEATURE_NAMES)), dtype=np.float32), np.empty(0, dtype=np.float32)
    return np.asarray(vectors, dtype=np.float32), np.asarray(labels, dtype=np.float32)


# ── drift detection ───────────────────────────────────────────────────────────

def _psi_feature(baseline: np.ndarray, current: np.ndarray, bins: int = 10) -> float:
    """Population Stability Index for one feature.

    PSI = sum((actual% - expected%) * ln(actual% / expected%))
    < 0.10 = stable, 0.10-0.25 = minor drift, > 0.25 = major drift.
    """
    edges = np.percentile(baseline, np.linspace(0, 100, bins + 1))
    edges[0] -= 1e-8
    edges[-1] += 1e-8

    base_counts = np.histogram(baseline, bins=edges)[0].astype(float)
    curr_counts = np.histogram(current, bins=edges)[0].astype(float)

    base_pct = np.where(base_counts == 0, 1e-8, base_counts / base_counts.sum())
    curr_pct = np.where(curr_counts == 0, 1e-8, curr_counts / curr_counts.sum())

    psi = np.sum((curr_pct - base_pct) * np.log(curr_pct / base_pct))
    return float(psi)


def detect_drift(
    background: np.ndarray,
    new_samples: np.ndarray,
) -> dict[str, Any]:
    """Compute PSI per feature and overall mean PSI."""
    if len(new_samples) < 20:
        return {"psi_mean": 0.0, "psi_per_feature": {}, "status": "insufficient_data"}

    psi_values: dict[str, float] = {}
    for i, name in enumerate(VERIFIER_FEATURE_NAMES):
        psi_values[name] = round(_psi_feature(background[:, i], new_samples[:, i]), 4)

    mean_psi = float(np.mean(list(psi_values.values())))
    top_drifted = sorted(psi_values.items(), key=lambda kv: kv[1], reverse=True)[:5]

    if mean_psi > _PSI_MAJOR_DRIFT:
        status = "major_drift"
    elif mean_psi > _PSI_STABLE:
        status = "minor_drift"
    else:
        status = "stable"

    return {
        "psi_mean": round(mean_psi, 4),
        "status": status,
        "top_drifted_features": [{"feature": k, "psi": v} for k, v in top_drifted],
        "recommendation": (
            "Schedule full retraining on updated datasets." if status == "major_drift"
            else "Fine-tune on analyst feedback." if status == "minor_drift"
            else "Model is stable; fine-tune if >= min_samples available."
        ),
    }


# ── fine-tuning ───────────────────────────────────────────────────────────────

def fine_tune(
    *,
    db_path: Path = _DB_PATH,
    hours: int = 168,            # default: look back 1 week
    min_samples: int = 30,
    epochs: int = _FT_EPOCHS,
    learning_rate: float = _FT_LR,
    batch_size: int = _FT_BATCH,
) -> dict[str, Any]:
    """Fine-tune on analyst feedback with drift detection and replay buffer.

    The replay buffer mixes a fraction of the stored background samples into
    every fine-tune batch so the model doesn't forget the original distribution
    (catastrophic forgetting prevention).
    """
    bundle = load_artifacts()
    if bundle is None:
        return {"status": "skipped", "reason": "no_artifact"}

    x_raw, y_feedback = _load_feedback_samples(db_path, hours)
    n_feedback = len(x_raw)

    # Drift analysis on raw (unnormalised) feedback vs normalised background.
    x_norm_feedback = (x_raw - bundle.mean) / bundle.std if n_feedback > 0 else x_raw
    drift_report = detect_drift(bundle.background, x_norm_feedback)

    if n_feedback < min_samples:
        return {
            "status": "skipped",
            "reason": "too_few_feedback_samples",
            "found": n_feedback,
            "required": min_samples,
            "drift": drift_report,
        }

    # ── build training set = feedback + replay buffer ─────────────────────────
    n_replay = max(1, int(n_feedback * _REPLAY_FRACTION / (1 - _REPLAY_FRACTION)))
    n_replay = min(n_replay, len(bundle.background))
    rng = np.random.default_rng(42)
    replay_idx = rng.choice(len(bundle.background), size=n_replay, replace=False)
    # Background vectors are already normalised; labels are 1.0 (confirmed good decisions).
    x_replay = bundle.background[replay_idx]
    y_replay = np.ones(n_replay, dtype=np.float32)

    x_all = np.vstack([x_norm_feedback, x_replay])
    y_all = np.concatenate([y_feedback, y_replay])

    x_tensor = torch.tensor(x_all, dtype=torch.float32)
    y_tensor = torch.tensor(y_all, dtype=torch.float32).unsqueeze(1)
    loader = DataLoader(TensorDataset(x_tensor, y_tensor), batch_size=batch_size, shuffle=True)

    # ── label balance ─────────────────────────────────────────────────────────
    n_neg = max(int((y_all == 0).sum()), 1)
    n_pos = max(int((y_all == 1).sum()), 1)
    pos_weight = torch.tensor([n_neg / n_pos], dtype=torch.float32)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    # ── train each ensemble member ────────────────────────────────────────────
    member_losses: list[float] = []
    for model in bundle.models:
        model.train()
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
        for _ in range(epochs):
            for bx, by in loader:
                optimizer.zero_grad()
                criterion(model(bx), by).backward()
                optimizer.step()
        model.eval()
        with torch.no_grad():
            member_losses.append(round(
                float(criterion(model(x_tensor), y_tensor).item()), 6
            ))

    save_artifacts(
        models=bundle.models,
        mean=bundle.mean,
        std=bundle.std,
        threshold=bundle.threshold,
        threat_threshold=bundle.threat_threshold,
        benign_threshold=bundle.benign_threshold,
        calibrator_slope=bundle.calibrator_slope,
        calibrator_intercept=bundle.calibrator_intercept,
        background=bundle.background,
        metadata=bundle.metadata,
        metrics=bundle.metrics,
    )

    verdict_counts = {}
    conn = sqlite3.connect(db_path)
    for v in _VERDICT_LABEL:
        count = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE analyst_verdict=? AND analyst_reviewed_at >= datetime('now', ?)",
            (v, f"-{hours} hours"),
        ).fetchone()[0]
        verdict_counts[v] = int(count)
    conn.close()

    return {
        "status": "ok",
        "feedback_samples": n_feedback,
        "replay_samples": n_replay,
        "total_training_samples": len(x_all),
        "epochs": epochs,
        "learning_rate": learning_rate,
        "verdict_breakdown": verdict_counts,
        "member_final_losses": member_losses,
        "drift": drift_report,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune verifier on analyst feedback.")
    parser.add_argument("--hours", type=int, default=168)
    parser.add_argument("--min-samples", type=int, default=30)
    parser.add_argument("--epochs", type=int, default=_FT_EPOCHS)
    parser.add_argument("--lr", type=float, default=_FT_LR)
    parser.add_argument("--db", type=str, default=str(_DB_PATH))
    args = parser.parse_args()

    import json as _j
    print(_j.dumps(fine_tune(
        db_path=Path(args.db),
        hours=args.hours,
        min_samples=args.min_samples,
        epochs=args.epochs,
        learning_rate=args.lr,
    ), indent=2))


if __name__ == "__main__":
    main()
