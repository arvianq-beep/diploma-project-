from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn

from .schema import METRICS_PATH, MODEL_INFO_PATH, MODEL_STATE_PATH, VERIFIER_FEATURE_NAMES


class VerifierMLP(nn.Module):
    """Compact MLP for backend-side decision verification."""

    def __init__(self, input_dim: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 48),
            nn.ReLU(),
            nn.Dropout(p=0.12),
            nn.Linear(48, 24),
            nn.ReLU(),
            nn.Linear(24, 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.network(features)


@dataclass(slots=True)
class VerifierArtifactBundle:
    """Loaded verifier model plus its normalization metadata."""

    model: VerifierMLP
    feature_names: list[str]
    mean: np.ndarray
    std: np.ndarray
    threshold: float
    metadata: dict[str, Any]
    metrics: dict[str, Any]

    def predict_probability(self, vector: list[float]) -> float:
        values = np.asarray(vector, dtype=np.float32)
        normalized = (values - self.mean) / self.std
        tensor = torch.tensor(normalized, dtype=torch.float32).unsqueeze(0)
        self.model.eval()
        with torch.no_grad():
            logits = self.model(tensor)
            probability = torch.sigmoid(logits).item()
        return float(probability)


def save_artifacts(
    model: VerifierMLP,
    mean: np.ndarray,
    std: np.ndarray,
    *,
    threshold: float,
    metadata: dict[str, Any],
    metrics: dict[str, Any],
    model_path: Path = MODEL_STATE_PATH,
    model_info_path: Path = MODEL_INFO_PATH,
    metrics_path: Path = METRICS_PATH,
) -> None:
    """Persist the verifier network and normalization statistics."""

    payload = {
        "state_dict": model.state_dict(),
        "feature_names": VERIFIER_FEATURE_NAMES,
        "input_dim": len(VERIFIER_FEATURE_NAMES),
        "mean": mean.tolist(),
        "std": std.tolist(),
        "threshold": threshold,
    }
    torch.save(payload, model_path)
    model_info_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")


def load_artifacts(
    model_path: Path = MODEL_STATE_PATH,
    model_info_path: Path = MODEL_INFO_PATH,
    metrics_path: Path = METRICS_PATH,
) -> VerifierArtifactBundle | None:
    """Load persisted verifier artifacts if available."""

    if not model_path.exists():
        return None

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
    input_dim = int(checkpoint.get("input_dim", len(VERIFIER_FEATURE_NAMES)))
    model = VerifierMLP(input_dim=input_dim)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()

    metadata = _load_json(model_info_path)
    metrics = _load_json(metrics_path)
    mean = np.asarray(checkpoint["mean"], dtype=np.float32)
    std = np.asarray(checkpoint["std"], dtype=np.float32)
    std[std == 0] = 1.0

    return VerifierArtifactBundle(
        model=model,
        feature_names=list(checkpoint.get("feature_names", VERIFIER_FEATURE_NAMES)),
        mean=mean,
        std=std,
        threshold=float(checkpoint.get("threshold", 0.58)),
        metadata=metadata,
        metrics=metrics,
    )


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
