from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from .schema import METRICS_PATH, MODEL_INFO_PATH, MODEL_STATE_PATH, VERIFIER_FEATURE_NAMES

try:
    import torch
    from torch import nn

    class VerifierMLP(nn.Module):
        """Expanded tabular MLP: input→128→64→32→1 with BatchNorm and Dropout."""

        def __init__(self, input_dim: int):
            super().__init__()
            self.network = nn.Sequential(
                nn.Linear(input_dim, 128),
                nn.BatchNorm1d(128),
                nn.ReLU(),
                nn.Dropout(p=0.20),
                nn.Linear(128, 64),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.Dropout(p=0.15),
                nn.Linear(64, 32),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.Dropout(p=0.10),
                nn.Linear(32, 1),
            )

        def forward(self, features: torch.Tensor) -> torch.Tensor:
            return self.network(features)

    _TORCH_AVAILABLE = True

except ImportError:
    _TORCH_AVAILABLE = False
    torch = None  # type: ignore[assignment]

    class VerifierMLP:  # type: ignore[no-redef]
        pass


def _enable_mc_dropout(model: VerifierMLP) -> None:
    """Freeze BatchNorm (eval) but keep Dropout active for MC sampling."""
    model.eval()
    for m in model.modules():
        if isinstance(m, nn.Dropout):
            m.train()


@dataclass(slots=True)
class VerifierArtifactBundle:
    """Loaded verifier ensemble with calibration, separate thresholds, and IG background."""

    models: list[VerifierMLP]      # ensemble — N independently trained models
    feature_names: list[str]
    mean: np.ndarray
    std: np.ndarray
    threshold: float               # general threshold kept for backward-compat
    threat_threshold: float        # Youden-J optimised for threat decisions
    benign_threshold: float        # Youden-J optimised for benign decisions
    calibrator_slope: float        # Platt scaling: sigmoid(slope * p + intercept)
    calibrator_intercept: float
    background: np.ndarray         # normalised reference vectors for integrated gradients
    metadata: dict[str, Any]
    metrics: dict[str, Any]

    # ── internal helpers ──────────────────────────────────────────────────────

    def _normalize(self, vector: list[float]) -> torch.Tensor:
        values = np.asarray(vector, dtype=np.float32)
        return torch.tensor((values - self.mean) / self.std, dtype=torch.float32).unsqueeze(0)

    def _calibrate(self, raw_prob: float) -> float:
        """Platt scaling maps raw ensemble mean to a calibrated probability."""
        logit = self.calibrator_slope * raw_prob + self.calibrator_intercept
        return float(1.0 / (1.0 + math.exp(-logit)))

    # ── public prediction API ─────────────────────────────────────────────────

    def predict_probability(self, vector: list[float]) -> float:
        """Ensemble mean probability, Platt-calibrated."""
        tensor = self._normalize(vector)
        probs: list[float] = []
        for model in self.models:
            model.eval()
            with torch.no_grad():
                probs.append(float(torch.sigmoid(model(tensor)).item()))
        return self._calibrate(float(np.mean(probs)))

    def predict_with_uncertainty(self, vector: list[float], n_samples: int = 30) -> dict[str, float]:
        """MC Dropout over the full ensemble (N_models × n_samples passes).

        BatchNorm runs in eval mode (uses stored running statistics) while
        Dropout layers stay active, giving calibrated epistemic uncertainty.
        """
        tensor = self._normalize(vector)
        all_probs: list[float] = []
        for model in self.models:
            _enable_mc_dropout(model)
            with torch.no_grad():
                for _ in range(n_samples):
                    all_probs.append(float(torch.sigmoid(model(tensor)).item()))
            model.eval()

        arr = np.asarray(all_probs, dtype=np.float64)
        return {
            "mean": self._calibrate(float(arr.mean())),
            "std": float(arr.std()),
            "min": self._calibrate(float(arr.min())),
            "max": self._calibrate(float(arr.max())),
            "uncertain": bool(arr.std() > 0.12),
        }

    def feature_importance(self, vector: list[float], steps: int = 50) -> dict[str, float]:
        """Integrated Gradients attribution averaged over the ensemble.

        Uses the mean of stored background samples as the baseline so that
        attributions reflect deviation from typical benign/mixed traffic.
        """
        if not _TORCH_AVAILABLE:
            return {}

        values = np.asarray(vector, dtype=np.float32)
        normalized = (values - self.mean) / self.std
        target = torch.tensor(normalized, dtype=torch.float32)
        baseline = torch.tensor(self.background.mean(axis=0), dtype=torch.float32)

        delta = (target - baseline).numpy()
        total_attr = np.zeros(len(vector), dtype=np.float64)

        for model in self.models:
            model.eval()
            # Interpolate from baseline to input in `steps` steps
            alphas = torch.stack([
                baseline + (i / steps) * (target - baseline)
                for i in range(steps + 1)
            ])  # (steps+1, n_features)
            alphas = alphas.detach().requires_grad_(True)

            with torch.enable_grad():
                logits = model(alphas)          # (steps+1, 1)
                probs = torch.sigmoid(logits).sum()
                probs.backward()

            grads = alphas.grad.detach().numpy()   # (steps+1, n_features)
            total_attr += grads.mean(axis=0) * delta

        total_attr /= len(self.models)
        importance = {
            name: round(float(val), 6)
            for name, val in zip(self.feature_names, total_attr)
        }
        # Return sorted by absolute attribution magnitude
        return dict(sorted(importance.items(), key=lambda kv: abs(kv[1]), reverse=True))


# ── artifact persistence ───────────────────────────────────────────────────────

def save_artifacts(
    models: list[VerifierMLP],
    mean: np.ndarray,
    std: np.ndarray,
    *,
    threshold: float,
    threat_threshold: float,
    benign_threshold: float,
    calibrator_slope: float,
    calibrator_intercept: float,
    background: np.ndarray,
    metadata: dict[str, Any],
    metrics: dict[str, Any],
    model_path: Path = MODEL_STATE_PATH,
    model_info_path: Path = MODEL_INFO_PATH,
    metrics_path: Path = METRICS_PATH,
) -> None:
    if not _TORCH_AVAILABLE:
        raise RuntimeError("PyTorch is required to save verifier artifacts.")

    payload = {
        "state_dicts": [m.state_dict() for m in models],
        "ensemble_size": len(models),
        "feature_names": VERIFIER_FEATURE_NAMES,
        "input_dim": len(VERIFIER_FEATURE_NAMES),
        "mean": mean.tolist(),
        "std": std.tolist(),
        "threshold": threshold,
        "threat_threshold": threat_threshold,
        "benign_threshold": benign_threshold,
        "calibrator_slope": calibrator_slope,
        "calibrator_intercept": calibrator_intercept,
        "background": background.tolist(),
    }
    torch.save(payload, model_path)  # type: ignore[union-attr]
    model_info_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")


def load_artifacts(
    model_path: Path = MODEL_STATE_PATH,
    model_info_path: Path = MODEL_INFO_PATH,
    metrics_path: Path = METRICS_PATH,
) -> VerifierArtifactBundle | None:
    if not _TORCH_AVAILABLE or not model_path.exists():
        return None

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)  # type: ignore[union-attr]
    input_dim = int(checkpoint.get("input_dim", len(VERIFIER_FEATURE_NAMES)))

    # Backward-compat: old format has a single `state_dict`; new format has `state_dicts`.
    if "state_dicts" in checkpoint:
        state_dicts = checkpoint["state_dicts"]
    else:
        state_dicts = [checkpoint["state_dict"]]

    models: list[VerifierMLP] = []
    for sd in state_dicts:
        m = VerifierMLP(input_dim=input_dim)
        m.load_state_dict(sd)
        m.eval()
        models.append(m)

    mean = np.asarray(checkpoint["mean"], dtype=np.float32)
    std = np.asarray(checkpoint["std"], dtype=np.float32)
    std[std == 0] = 1.0

    raw_bg = checkpoint.get("background", [])
    background = np.asarray(raw_bg, dtype=np.float32) if raw_bg else np.zeros((1, input_dim), dtype=np.float32)

    return VerifierArtifactBundle(
        models=models,
        feature_names=list(checkpoint.get("feature_names", VERIFIER_FEATURE_NAMES)),
        mean=mean,
        std=std,
        threshold=float(checkpoint.get("threshold", 0.58)),
        threat_threshold=float(checkpoint.get("threat_threshold", checkpoint.get("threshold", 0.58))),
        benign_threshold=float(checkpoint.get("benign_threshold", checkpoint.get("threshold", 0.58))),
        calibrator_slope=float(checkpoint.get("calibrator_slope", 1.0)),
        calibrator_intercept=float(checkpoint.get("calibrator_intercept", 0.0)),
        background=background,
        metadata=_load_json(model_info_path),
        metrics=_load_json(metrics_path),
    )


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
