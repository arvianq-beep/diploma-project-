from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from ml.inference import MLPredictor
from ml.preprocessing import DatasetBundle, harmonize_frame, load_dataset_bundle

from .features import (
    context_consistency_score,
    cross_evidence_score,
    detector_feature_map,
    event_feature_map,
    perturbation_feature_map,
    raw_indicator_feature_map,
    run_perturbation_analysis_batch,
    synthesize_event_from_snapshot,
)
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


def rows_from_bundle(
    bundle: DatasetBundle,
    predictor: MLPredictor,
    max_samples: int | None = None,
    seed: int = 42,
) -> list[TrainingRow]:
    """Generate verifier training rows from detector outputs and real ground-truth labels.

    Batch implementation — predict_proba is called exactly 3 times regardless of N:
      • Call 1: main attack probabilities for all N rows (predict_from_features_batch)
      • Call 2: stability perturbations for all N rows (stacked 5×N DataFrame)
      • Call 3: perturbation variants for all N×6 rows (run_perturbation_analysis_batch)

    When max_samples is set, a stratified sample is drawn so that the attack/benign
    ratio is preserved before any RF inference runs.
    """
    frame = bundle.frame
    labels = bundle.labels

    if max_samples is not None and len(frame) > max_samples:
        attack_idx = labels[labels == 1].index
        benign_idx = labels[labels == 0].index
        attack_quota = min(len(attack_idx), max(1, int(max_samples * len(attack_idx) / len(labels))))
        benign_quota = max_samples - attack_quota
        rng = np.random.default_rng(seed)
        sampled_attack = rng.choice(attack_idx, size=min(attack_quota, len(attack_idx)), replace=False)
        sampled_benign = rng.choice(benign_idx, size=min(benign_quota, len(benign_idx)), replace=False)
        selected = np.concatenate([sampled_attack, sampled_benign])
        rng.shuffle(selected)
        frame = frame.loc[selected]
        labels = labels.loc[selected]

    original_indices = list(frame.index)

    # ── phase 1: build all events (no RF calls) ───────────────────────────────
    # to_dict(orient='records') is ~10× faster than iterrows() for bulk conversion.
    snapshots: list[dict[str, Any]] = frame.to_dict(orient="records")
    events: list[dict[str, Any]] = [
        synthesize_event_from_snapshot(
            snap,
            event_id=f"{bundle.dataset_name}-{row_idx}",
            title=f"{bundle.dataset_name} sample {i}",
            source=bundle.dataset_name,
        )
        for i, (snap, row_idx) in enumerate(zip(snapshots, original_indices))
    ]

    # ── phase 2: batch Stage-1 inference (2 predict_proba calls) ─────────────
    detector_outputs = predictor.predict_from_features_batch(snapshots, events)

    # ── phase 3: batch perturbation analysis (1 predict_proba call) ──────────
    perturbations = run_perturbation_analysis_batch(predictor, snapshots, detector_outputs)

    # ── phase 4: assemble verifier vectors and pseudo-labels (no RF calls) ───
    rows: list[TrainingRow] = []
    for i, (event, det_out, perturb) in enumerate(zip(events, detector_outputs, perturbations)):
        context_score = context_consistency_score(event=event, detector_output=det_out)
        evidence_score = cross_evidence_score(event=event, detector_output=det_out)

        benign_alignment = (
            (1.0 - float(event.get("anomaly_score", 0.0)))
            + (1.0 - float(event.get("context_risk_score", 0.0)))
            + (1.0 - evidence_score)
        ) / 3.0
        threat_alignment = (context_score + evidence_score + det_out.confidence) / 3.0
        support_score = float(max(0.0, min(1.0, benign_alignment if det_out.label == "Benign" else threat_alignment)))

        feature_map = {
            **event_feature_map(event),
            **detector_feature_map(det_out),
            **perturbation_feature_map(perturb),
            "context_consistency_score": round(context_score, 6),
            "cross_evidence_score": round(evidence_score, 6),
            "support_alignment_score": round(support_score, 6),
            **raw_indicator_feature_map(event, det_out),
        }
        vector = [float(feature_map[name]) for name in VERIFIER_FEATURE_NAMES]

        target, reason = generate_verification_target(
            detector_label=det_out.label,
            detector_confidence=det_out.confidence,
            detector_stability=det_out.stability_score,
            perturbation_label_consistency=perturb.label_consistency_ratio,
            confidence_drop=perturb.confidence_drop,
            ground_truth=int(labels.iloc[i]),
        )
        rows.append(TrainingRow(
            features=vector,
            label=target,
            reason=reason,
            metadata={
                "ground_truth": int(bundle.labels.iloc[i]),
                "detector_label": det_out.label,
                "detector_confidence": round(det_out.confidence, 4),
            },
        ))
    return rows


def generate_verification_target(
    *,
    detector_label: str,
    detector_confidence: float,
    detector_stability: float,
    perturbation_label_consistency: float,
    confidence_drop: float,
    ground_truth: int,
) -> tuple[int, str]:
    """Pseudo-label whether the detector decision is trustworthy enough to verify.

    Labels are based ONLY on ground truth correctness and perturbation stability.
    The computed scores (context, evidence, alignment) are intentionally excluded
    from the label criteria because they are also MLP input features — using them
    as labeling thresholds would create circular reasoning where the network simply
    learns to reproduce the rule thresholds rather than genuinely generalising.
    """

    predicted_attack = detector_label != "Benign"
    correct = predicted_attack == bool(ground_truth)
    # Stability: requires consistent label and bounded confidence drop under perturbation.
    # Minimum confidence per direction prevents low-confidence lucky-correct detections.
    min_confidence = 0.62 if predicted_attack else 0.56
    stable = (
        detector_stability >= 0.58
        and perturbation_label_consistency >= 0.74
        and confidence_drop <= 0.18
        and detector_confidence >= min_confidence
    )

    verified = correct and stable
    if predicted_attack:
        reason = "correct+stable-threat" if verified else "untrusted-threat"
    else:
        reason = "correct+stable-benign" if verified else "untrusted-benign"

    return (1 if verified else 0), reason


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


_ENSEMBLE_SEEDS = [42, 137, 999]
_DETECTOR_IS_THREAT_IDX = VERIFIER_FEATURE_NAMES.index("detector_is_threat")


def _train_single_model(
    *,
    x_train_norm: torch.Tensor,
    y_train: np.ndarray,
    val_features: torch.Tensor,
    val_targets: torch.Tensor,
    model_seed: int,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    pos_weight: torch.Tensor,
) -> tuple[VerifierMLP, list[dict[str, float]]]:
    """Train one MLP member of the ensemble and return the best-val-loss checkpoint."""
    torch.manual_seed(model_seed)
    model = VerifierMLP(input_dim=len(VERIFIER_FEATURE_NAMES))
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    dataset = TensorDataset(
        x_train_norm,
        torch.tensor(y_train, dtype=torch.float32).unsqueeze(1),
    )
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    best_state: dict | None = None
    best_val_loss = float("inf")
    history: list[dict[str, float]] = []

    for epoch in range(epochs):
        model.train()
        train_losses: list[float] = []
        for batch_x, batch_y in loader:
            optimizer.zero_grad()
            loss = criterion(model(batch_x), batch_y)
            loss.backward()
            optimizer.step()
            train_losses.append(float(loss.item()))

        model.eval()
        with torch.no_grad():
            val_loss = float(criterion(model(val_features), val_targets).item())
        history.append({
            "epoch": float(epoch + 1),
            "train_loss": round(float(np.mean(train_losses)), 6),
            "val_loss": round(val_loss, 6),
        })
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()
    return model, history


def _youden_threshold(y_true: np.ndarray, probs: np.ndarray) -> float:
    if len(np.unique(y_true)) < 2:
        return 0.50
    fpr, tpr, thr = roc_curve(y_true, probs)
    best = thr[np.argmax(tpr - fpr)]
    return round(float(np.clip(best, 0.30, 0.90)), 4)


def train_verifier(
    *,
    cic_path: str | None,
    unsw_path: str | None,
    bootstrap_samples: int,
    max_samples_per_dataset: int | None,
    seed: int,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    heuristic_detector: bool,
) -> dict[str, Any]:
    """Train an ensemble of MLP verifiers with Platt calibration and separate thresholds."""

    np.random.seed(seed)

    predictor = (
        MLPredictor(model_path="missing_detector_artifact.joblib")
        if heuristic_detector
        else MLPredictor()
    )
    bundles: list[DatasetBundle] = []
    if cic_path:
        full_cic = load_dataset_bundle(cic_path, "cic_ids2017")
        _, cic_test_frame, _, cic_test_labels = train_test_split(
            full_cic.frame,
            full_cic.labels,
            test_size=0.2,
            random_state=42,
            stratify=full_cic.labels,
        )
        bundles.append(DatasetBundle(
            frame=cic_test_frame.reset_index(drop=True),
            labels=cic_test_labels.reset_index(drop=True),
            dataset_name="cic_ids2017_held_out",
            source_files=full_cic.source_files,
            dataset_audit=full_cic.dataset_audit,
            rows_before_dedup=len(cic_test_frame),
            rows_after_dedup=len(cic_test_frame),
            merged_duplicates_removed=0,
        ))
    if unsw_path:
        bundles.append(load_dataset_bundle(unsw_path, "unsw_nb15_augmented"))
    if not bundles:
        bundles.append(build_bootstrap_dataset(sample_count=bootstrap_samples, seed=seed))

    training_rows: list[TrainingRow] = []
    for bundle in bundles:
        training_rows.extend(
            rows_from_bundle(bundle, predictor, max_samples=max_samples_per_dataset, seed=seed)
        )

    features, labels = split_arrays(training_rows)
    x_train, x_temp, y_train, y_temp = train_test_split(
        features, labels, test_size=0.3, random_state=seed, stratify=labels.astype(int),
    )
    x_val, x_test, y_val, y_test = train_test_split(
        x_temp, y_temp, test_size=0.5, random_state=seed, stratify=y_temp.astype(int),
    )

    mean = x_train.mean(axis=0)
    std = x_train.std(axis=0)
    std[std == 0] = 1.0

    x_train_norm = torch.tensor((x_train - mean) / std, dtype=torch.float32)
    val_features = torch.tensor((x_val - mean) / std, dtype=torch.float32)
    val_targets = torch.tensor(y_val, dtype=torch.float32).unsqueeze(1)
    test_features = torch.tensor((x_test - mean) / std, dtype=torch.float32)

    n_neg = max(int((y_train == 0).sum()), 1)
    n_pos = max(int((y_train == 1).sum()), 1)
    pos_weight = torch.tensor([n_neg / n_pos], dtype=torch.float32)

    # ── Train ensemble ─────────────────────────────────────────────────────────
    ensemble: list[VerifierMLP] = []
    all_histories: list[list[dict]] = []
    for model_seed in _ENSEMBLE_SEEDS:
        print(f"  Training ensemble member seed={model_seed} ...")
        m, hist = _train_single_model(
            x_train_norm=x_train_norm,
            y_train=y_train,
            val_features=val_features,
            val_targets=val_targets,
            model_seed=model_seed,
            epochs=epochs,
            batch_size=batch_size,
            learning_rate=learning_rate,
            pos_weight=pos_weight,
        )
        ensemble.append(m)
        all_histories.append(hist)

    # ── Ensemble probabilities on val and test ─────────────────────────────────
    with torch.no_grad():
        val_member_probs = np.stack([
            torch.sigmoid(m(val_features)).squeeze(1).numpy() for m in ensemble
        ])  # (n_members, n_val)
        test_member_probs = np.stack([
            torch.sigmoid(m(test_features)).squeeze(1).numpy() for m in ensemble
        ])

    val_prob = val_member_probs.mean(axis=0)
    test_prob = test_member_probs.mean(axis=0)

    # ── Platt scaling calibration (fit sigmoid on val predictions) ─────────────
    cal = LogisticRegression(C=1e10, solver="lbfgs", max_iter=1000)
    cal.fit(val_prob.reshape(-1, 1), y_val.astype(int))
    calibrator_slope = float(cal.coef_[0][0])
    calibrator_intercept = float(cal.intercept_[0])
    val_prob_cal = cal.predict_proba(val_prob.reshape(-1, 1))[:, 1]
    test_prob_cal = cal.predict_proba(test_prob.reshape(-1, 1))[:, 1]

    # ── Youden-J general threshold on calibrated val probabilities ─────────────
    threshold = _youden_threshold(y_val, val_prob_cal)

    # ── Separate threat / benign thresholds ───────────────────────────────────
    # Split val by detector decision direction to optimise each independently.
    threat_mask = x_val[:, _DETECTOR_IS_THREAT_IDX] > 0.5
    benign_mask = ~threat_mask
    threat_threshold = (
        _youden_threshold(y_val[threat_mask], val_prob_cal[threat_mask])
        if threat_mask.sum() > 10 else threshold
    )
    benign_threshold = (
        _youden_threshold(y_val[benign_mask], val_prob_cal[benign_mask])
        if benign_mask.sum() > 10 else threshold
    )

    # ── Background samples for Integrated Gradients ───────────────────────────
    # 100 random normalised training vectors serve as the IG reference baseline.
    rng = np.random.default_rng(seed)
    bg_idx = rng.choice(len(x_train), size=min(100, len(x_train)), replace=False)
    background = ((x_train[bg_idx] - mean) / std).astype(np.float32)

    label_reasons = pd.Series([row.reason for row in training_rows]).value_counts().to_dict()
    metrics = {
        "model_type": "ensemble_tabular_mlp_verifier",
        "model_version": "verifier-ensemble-mlp-v2",
        "ensemble_size": len(ensemble),
        "ensemble_seeds": _ENSEMBLE_SEEDS,
        "input_features": VERIFIER_FEATURE_NAMES,
        "threshold": threshold,
        "threat_threshold": threat_threshold,
        "benign_threshold": benign_threshold,
        "calibrator_slope": round(calibrator_slope, 6),
        "calibrator_intercept": round(calibrator_intercept, 6),
        "train_rows": int(len(x_train)),
        "validation_rows": int(len(x_val)),
        "test_rows": int(len(x_test)),
        "label_distribution": {
            "verified": int(labels.sum()),
            "not_verified": int(len(labels) - labels.sum()),
        },
        "label_generation_reasons": {str(k): int(v) for k, v in label_reasons.items()},
        "validation": compute_metrics(y_val, val_prob_cal, threshold),
        "test": compute_metrics(y_test, test_prob_cal, threshold),
        "training_history_tail": {
            f"seed_{s}": h[-5:] for s, h in zip(_ENSEMBLE_SEEDS, all_histories)
        },
    }
    metadata = {
        "model_name": "Secure Decision Verification Ensemble MLP",
        "model_version": "verifier-ensemble-mlp-v2",
        "architecture": {
            "type": "ensemble_mlp",
            "ensemble_size": len(ensemble),
            "hidden_layers": [128, 64, 32],
            "dropout": [0.20, 0.15, 0.10],
            "batch_norm": True,
            "activation": "relu",
            "calibration": "platt_scaling",
        },
        "threshold": threshold,
        "threat_threshold": threat_threshold,
        "benign_threshold": benign_threshold,
        "input_features": VERIFIER_FEATURE_NAMES,
        "training_sources": [b.dataset_name for b in bundles],
        "detector_training_mode": "heuristic-fallback" if heuristic_detector else "trained-detector-artifact",
        "label_generation": {
            "description": (
                "Pseudo-labels based on ground-truth correctness and perturbation stability only. "
                "Computed scores excluded from label criteria to prevent circular reasoning. "
                "CIC-IDS2017 uses only the held-out 20% split (test_size=0.2, random_state=42). "
                "UNSW-NB15 is used in full (never used in Stage 1 training)."
            ),
            "attack_rule": "verified = detector correct AND confidence >= 0.62 AND stability >= 0.58 AND label_consistency >= 0.74 AND confidence_drop <= 0.18",
            "benign_rule": "verified = detector correct AND confidence >= 0.56 AND stability >= 0.58 AND label_consistency >= 0.74 AND confidence_drop <= 0.18",
        },
        "seed": seed,
    }

    save_artifacts(
        models=ensemble,
        mean=mean,
        std=std,
        threshold=threshold,
        threat_threshold=threat_threshold,
        benign_threshold=benign_threshold,
        calibrator_slope=calibrator_slope,
        calibrator_intercept=calibrator_intercept,
        background=background,
        metadata=metadata,
        metrics=metrics,
    )
    return {"metadata": metadata, "metrics": metrics}


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the backend Secure Decision Verification MLP.")
    parser.add_argument("--cic", help="Path to CIC-IDS2017 CSV file or directory")
    parser.add_argument("--unsw", help="Path to CIC-UNSW-NB15 CSV file or directory")
    parser.add_argument("--bootstrap-samples", type=int, default=2400)
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Stratified sample cap per dataset before per-row RF inference (e.g. 30000). "
             "Required when datasets are large; preserves attack/benign ratio.",
    )
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
        max_samples_per_dataset=args.max_samples,
        seed=args.seed,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        heuristic_detector=args.heuristic_detector,
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
