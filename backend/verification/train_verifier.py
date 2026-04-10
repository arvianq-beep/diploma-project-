from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from ml.inference import MLPredictor
from ml.preprocessing import DatasetBundle, harmonize_frame, load_dataset_bundle

from .features import build_verification_features, synthesize_event_from_snapshot
from .model import VerifierMLP, save_artifacts
from .schema import VERIFIER_FEATURE_NAMES


@dataclass(slots=True)
class TrainingRow:
    features: list[float]
    label: int
    reason: str
    metadata: dict[str, Any]


def build_bootstrap_dataset(sample_count: int, seed: int) -> DatasetBundle:
    """Create a reproducible synthetic flow dataset when no real dataset is available."""

    rng = np.random.default_rng(seed)
    rows: list[dict[str, Any]] = []
    labels: list[int] = []

    for index in range(sample_count):
        attack = 1 if index % 2 else 0
        if attack:
            protocol = rng.choice(["TCP", "UDP", "ICMP"], p=[0.55, 0.20, 0.25])
            destination_port = int(rng.choice([22, 23, 80, 443, 3389], p=[0.22, 0.14, 0.12, 0.16, 0.36]))
            duration = float(rng.uniform(0.2, 15.0))
            forward_packets = float(rng.uniform(240, 4200))
            backward_packets = float(rng.uniform(80, 2600))
            forward_bytes = float(rng.uniform(60_000, 2_400_000))
            backward_bytes = float(rng.uniform(12_000, 900_000))
            bytes_per_second = float(rng.uniform(120_000, 520_000))
            packets_per_second = float(rng.uniform(260, 1400))
        else:
            protocol = rng.choice(["TCP", "UDP", "ICMP"], p=[0.78, 0.18, 0.04])
            destination_port = int(rng.choice([53, 80, 443, 8080, 3306], p=[0.16, 0.28, 0.28, 0.16, 0.12]))
            duration = float(rng.uniform(0.3, 90.0))
            forward_packets = float(rng.uniform(20, 1200))
            backward_packets = float(rng.uniform(10, 900))
            forward_bytes = float(rng.uniform(1_000, 240_000))
            backward_bytes = float(rng.uniform(800, 160_000))
            bytes_per_second = float(rng.uniform(400, 220_000))
            packets_per_second = float(rng.uniform(1, 380))

        rows.append(
            {
                "protocol": protocol,
                "source_port": int(rng.integers(1024, 65535)),
                "destination_port": destination_port,
                "duration": duration,
                "forward_packets": forward_packets,
                "backward_packets": backward_packets,
                "forward_bytes": forward_bytes,
                "backward_bytes": backward_bytes,
                "bytes_per_second": bytes_per_second,
                "packets_per_second": packets_per_second,
            }
        )
        labels.append(attack)

    frame = pd.DataFrame(rows)
    labels_series = pd.Series(labels, dtype=int)
    return DatasetBundle(
        frame=harmonize_frame(frame, "unsw_nb15_augmented"),
        labels=labels_series,
        dataset_name="bootstrap_synthetic",
        source_files=["synthetic-seed"],
        dataset_audit=[{"file": "synthetic-seed", "rows": sample_count}],
        rows_before_dedup=sample_count,
        rows_after_dedup=sample_count,
        merged_duplicates_removed=0,
    )


def rows_from_bundle(bundle: DatasetBundle, predictor: MLPredictor) -> list[TrainingRow]:
    """Generate verifier training rows from detector outputs and heuristic targets."""

    rows: list[TrainingRow] = []
    for index, (row_index, snapshot) in enumerate(bundle.frame.iterrows()):
        canonical = snapshot.to_dict()
        event = synthesize_event_from_snapshot(
            canonical,
            event_id=f"{bundle.dataset_name}-{row_index}",
            title=f"{bundle.dataset_name} sample {index}",
            source=bundle.dataset_name,
        )
        detector_output = predictor.predict_from_features(canonical, context=event)
        features = build_verification_features(
            predictor=predictor,
            event=event,
            detector_output=detector_output,
        )
        target, reason = generate_verification_target(
            detector_label=detector_output.label,
            detector_confidence=detector_output.confidence,
            detector_stability=detector_output.stability_score,
            perturbation_label_consistency=features.perturbation.label_consistency_ratio,
            confidence_drop=features.perturbation.confidence_drop,
            context_score=features.context_consistency_score,
            cross_evidence_score=features.cross_evidence_score,
            support_alignment_score=features.support_alignment_score,
            ground_truth=int(bundle.labels.iloc[index]),
        )
        rows.append(
            TrainingRow(
                features=features.vector,
                label=target,
                reason=reason,
                metadata={
                    "ground_truth": int(bundle.labels.iloc[index]),
                    "detector_label": detector_output.label,
                    "detector_confidence": round(detector_output.confidence, 4),
                },
            )
        )
    return rows


def generate_verification_target(
    *,
    detector_label: str,
    detector_confidence: float,
    detector_stability: float,
    perturbation_label_consistency: float,
    confidence_drop: float,
    context_score: float,
    cross_evidence_score: float,
    support_alignment_score: float,
    ground_truth: int,
) -> tuple[int, str]:
    """Pseudo-label whether the detector decision is trustworthy enough to verify."""

    predicted_attack = detector_label != "Benign"
    correct = predicted_attack == bool(ground_truth)
    stable = detector_stability >= 0.58 and perturbation_label_consistency >= 0.74 and confidence_drop <= 0.18

    if predicted_attack:
        supported = (
            detector_confidence >= 0.62
            and context_score >= 0.48
            and cross_evidence_score >= 0.54
            and support_alignment_score >= 0.56
        )
        reason = "correct+stable+supported-threat" if correct and stable and supported else "untrusted-threat"
    else:
        supported = (
            detector_confidence >= 0.56
            and context_score >= 0.52
            and cross_evidence_score <= 0.46
            and support_alignment_score >= 0.54
        )
        reason = "correct+stable+supported-benign" if correct and stable and supported else "untrusted-benign"

    return (1 if correct and stable and supported else 0), reason


def split_arrays(rows: list[TrainingRow]) -> tuple[np.ndarray, np.ndarray]:
    features = np.asarray([row.features for row in rows], dtype=np.float32)
    labels = np.asarray([row.label for row in rows], dtype=np.float32)
    return features, labels


def compute_metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict[str, float]:
    predictions = (probabilities >= threshold).astype(int)
    metrics = {
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "precision": round(float(precision_score(y_true, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, predictions, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, predictions, zero_division=0)), 4),
    }
    if len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, probabilities)), 4)
    return metrics


def train_verifier(
    *,
    cic_path: str | None,
    unsw_path: str | None,
    bootstrap_samples: int,
    seed: int,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    heuristic_detector: bool,
) -> dict[str, Any]:
    """Train the tabular MLP verifier and save artifacts."""

    torch.manual_seed(seed)
    np.random.seed(seed)

    predictor = (
        MLPredictor(model_path="missing_detector_artifact.joblib")
        if heuristic_detector
        else MLPredictor()
    )
    bundles: list[DatasetBundle] = []
    if cic_path:
        bundles.append(load_dataset_bundle(cic_path, "cic_ids2017"))
    if unsw_path:
        bundles.append(load_dataset_bundle(unsw_path, "unsw_nb15_augmented"))
    if not bundles:
        bundles.append(build_bootstrap_dataset(sample_count=bootstrap_samples, seed=seed))

    training_rows: list[TrainingRow] = []
    for bundle in bundles:
        training_rows.extend(rows_from_bundle(bundle, predictor))

    features, labels = split_arrays(training_rows)
    x_train, x_temp, y_train, y_temp = train_test_split(
        features,
        labels,
        test_size=0.3,
        random_state=seed,
        stratify=labels.astype(int),
    )
    x_val, x_test, y_val, y_test = train_test_split(
        x_temp,
        y_temp,
        test_size=0.5,
        random_state=seed,
        stratify=y_temp.astype(int),
    )

    mean = x_train.mean(axis=0)
    std = x_train.std(axis=0)
    std[std == 0] = 1.0

    train_tensor = TensorDataset(
        torch.tensor((x_train - mean) / std, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.float32).unsqueeze(1),
    )
    val_features = torch.tensor((x_val - mean) / std, dtype=torch.float32)
    val_targets = torch.tensor(y_val, dtype=torch.float32).unsqueeze(1)
    test_features = torch.tensor((x_test - mean) / std, dtype=torch.float32)

    loader = DataLoader(train_tensor, batch_size=batch_size, shuffle=True)
    model = VerifierMLP(input_dim=len(VERIFIER_FEATURE_NAMES))
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.BCEWithLogitsLoss()

    best_state = None
    best_val_loss = float("inf")
    history: list[dict[str, float]] = []

    for epoch in range(epochs):
        model.train()
        train_losses: list[float] = []
        for batch_features, batch_targets in loader:
            optimizer.zero_grad()
            logits = model(batch_features)
            loss = criterion(logits, batch_targets)
            loss.backward()
            optimizer.step()
            train_losses.append(float(loss.item()))

        model.eval()
        with torch.no_grad():
            val_logits = model(val_features)
            val_loss = float(criterion(val_logits, val_targets).item())
            history.append(
                {
                    "epoch": float(epoch + 1),
                    "train_loss": round(float(np.mean(train_losses)), 6),
                    "val_loss": round(val_loss, 6),
                }
            )
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {key: value.clone() for key, value in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)

    model.eval()
    with torch.no_grad():
        val_prob = torch.sigmoid(model(val_features)).squeeze(1).numpy()
        test_prob = torch.sigmoid(model(test_features)).squeeze(1).numpy()

    threshold = 0.58
    label_reasons = pd.Series([row.reason for row in training_rows]).value_counts().to_dict()
    metrics = {
        "model_type": "tabular_mlp_verifier",
        "model_version": "verifier-tabular-mlp-v1",
        "input_features": VERIFIER_FEATURE_NAMES,
        "threshold": threshold,
        "train_rows": int(len(x_train)),
        "validation_rows": int(len(x_val)),
        "test_rows": int(len(x_test)),
        "label_distribution": {
            "verified": int(labels.sum()),
            "not_verified": int(len(labels) - labels.sum()),
        },
        "label_generation_reasons": {str(key): int(value) for key, value in label_reasons.items()},
        "validation": compute_metrics(y_val, val_prob, threshold),
        "test": compute_metrics(y_test, test_prob, threshold),
        "training_history_tail": history[-10:],
    }
    metadata = {
        "model_name": "Secure Decision Verification MLP",
        "model_version": "verifier-tabular-mlp-v1",
        "architecture": {
            "type": "mlp",
            "hidden_layers": [48, 24],
            "dropout": 0.12,
            "activation": "relu",
        },
        "threshold": threshold,
        "input_features": VERIFIER_FEATURE_NAMES,
        "training_sources": [bundle.dataset_name for bundle in bundles],
        "detector_training_mode": "heuristic-fallback" if heuristic_detector else "trained-detector-artifact",
        "label_generation": {
            "description": (
                "Because the repository does not include human-labelled verification targets, "
                "the verifier is trained on pseudo-labels: a sample is marked verified only when "
                "the Stage 1 detector prediction matches ground truth and is simultaneously stable, "
                "confident, and context-supported."
            ),
            "attack_rule": "verified = detector correct AND confidence >= 0.62 AND stability >= 0.58 AND label_consistency >= 0.74 AND confidence_drop <= 0.18 AND context_score >= 0.48 AND cross_evidence_score >= 0.54 AND support_alignment_score >= 0.56",
            "benign_rule": "verified = detector correct AND confidence >= 0.56 AND stability >= 0.58 AND label_consistency >= 0.74 AND confidence_drop <= 0.18 AND context_score >= 0.52 AND cross_evidence_score <= 0.46 AND support_alignment_score >= 0.54",
        },
        "seed": seed,
    }

    save_artifacts(
        model=model,
        mean=mean,
        std=std,
        threshold=threshold,
        metadata=metadata,
        metrics=metrics,
    )
    return {"metadata": metadata, "metrics": metrics}


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the backend Secure Decision Verification MLP.")
    parser.add_argument("--cic", help="Path to CIC-IDS2017 CSV file or directory")
    parser.add_argument("--unsw", help="Path to CIC-UNSW-NB15 CSV file or directory")
    parser.add_argument("--bootstrap-samples", type=int, default=2400)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=26)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=0.0015)
    parser.add_argument(
        "--heuristic-detector",
        action="store_true",
        help="Use the detector heuristic path during verifier training for fast bootstrap artifact generation.",
    )
    args = parser.parse_args()

    results = train_verifier(
        cic_path=args.cic,
        unsw_path=args.unsw,
        bootstrap_samples=args.bootstrap_samples,
        seed=args.seed,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        heuristic_detector=args.heuristic_detector,
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
