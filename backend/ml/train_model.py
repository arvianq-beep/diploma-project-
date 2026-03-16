from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from joblib import dump
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .preprocessing import DatasetBundle, load_dataset_bundle
from .schema import CANONICAL_FEATURES, METRICS_PATH, MODEL_INFO_PATH, MODEL_PATH


NUMERIC_FEATURES = [
    "source_port",
    "destination_port",
    "duration",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "bytes_per_second",
    "packets_per_second",
]
CAT_FEATURES = ["protocol"]


def build_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                NUMERIC_FEATURES,
            ),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                CAT_FEATURES,
            ),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=320,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )


def metrics_from_predictions(y_true, y_pred, y_score) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_score)), 4),
        "pr_auc": round(float(average_precision_score(y_true, y_score)), 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def evaluate_bundle(pipeline: Pipeline, bundle: DatasetBundle) -> dict:
    probabilities = pipeline.predict_proba(bundle.frame)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    metrics = metrics_from_predictions(bundle.labels, predictions, probabilities)
    metrics["dataset"] = bundle.dataset_name
    metrics["rows"] = int(len(bundle.frame))
    metrics["source_files"] = bundle.source_files
    return metrics


def train(cic_path: str, unsw_path: str | None = None) -> dict:
    cic_bundle = load_dataset_bundle(cic_path, "cic_ids2017")

    X_train, X_test, y_train, y_test = train_test_split(
        cic_bundle.frame,
        cic_bundle.labels,
        test_size=0.2,
        random_state=42,
        stratify=cic_bundle.labels,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train,
        y_train,
        test_size=0.2,
        random_state=42,
        stratify=y_train,
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    val_prob = pipeline.predict_proba(X_val)[:, 1]
    val_pred = (val_prob >= 0.5).astype(int)
    test_prob = pipeline.predict_proba(X_test)[:, 1]
    test_pred = (test_prob >= 0.5).astype(int)

    results = {
        "model": {
            "model_name": "Random Forest",
            "model_version": "rf-cic-unsw-v1",
            "features": CANONICAL_FEATURES,
            "train_dataset": "CIC-IDS2017",
            "cross_dataset_evaluation": "CIC-UNSW-NB15 (Augmented)" if unsw_path else None,
        },
        "validation": metrics_from_predictions(y_val, val_pred, val_prob),
        "test": metrics_from_predictions(y_test, test_pred, test_prob),
        "train_rows": int(len(X_train)),
        "validation_rows": int(len(X_val)),
        "test_rows": int(len(X_test)),
    }

    if unsw_path:
        unsw_bundle = load_dataset_bundle(unsw_path, "unsw_nb15_augmented")
        results["cross_dataset"] = evaluate_bundle(pipeline, unsw_bundle)

    dump(pipeline, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    MODEL_INFO_PATH.write_text(
        json.dumps(
            {
                "model_name": "Random Forest",
                "model_version": "rf-cic-unsw-v1",
                "features": CANONICAL_FEATURES,
                "train_dataset": "CIC-IDS2017",
                "cross_dataset": "CIC-UNSW-NB15 (Augmented)" if unsw_path else None,
                "artifacts": {
                    "model_path": str(MODEL_PATH),
                    "metrics_path": str(METRICS_PATH),
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return results


def main():
    parser = argparse.ArgumentParser(description="Train IDS Random Forest model.")
    parser.add_argument("--cic", required=True, help="Path to CIC-IDS2017 CSV file or directory")
    parser.add_argument("--unsw", required=False, help="Path to CIC-UNSW-NB15 augmented CSV file or directory")
    args = parser.parse_args()

    results = train(args.cic, args.unsw)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
