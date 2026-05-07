from __future__ import annotations

import argparse
import json

import pandas as pd
from joblib import dump
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
from sklearn.preprocessing import StandardScaler

from .preprocessing import DatasetBundle, load_dataset_bundle
from .schema import CANONICAL_FEATURES, FEATURES_PATH, METRICS_PATH, MODEL_INFO_PATH, MODEL_PATH


def build_pipeline() -> Pipeline:
    """Build a sklearn Pipeline for the 77-feature canonical flow schema.

    All 77 canonical features are numeric after harmonize_frame(), so a
    ColumnTransformer is not needed — imputation and scaling are applied
    to the full feature matrix directly.
    """
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=320,
                    max_depth=18,
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def metrics_from_predictions(y_true, y_pred, y_score) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "attack_recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "false_positives": int(fp),
        "predicted_attack_ratio": round(float(pd.Series(y_pred).mean()), 4),
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
    probabilities = pipeline.predict_proba(bundle.frame[CANONICAL_FEATURES])[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    metrics = metrics_from_predictions(bundle.labels, predictions, probabilities)
    metrics["dataset"] = bundle.dataset_name
    metrics["rows"] = int(len(bundle.frame))
    metrics["source_files"] = bundle.source_files
    return metrics


def train(cic_path: str, unsw_path: str | None = None) -> dict:
    cic_bundle = load_dataset_bundle(cic_path, "cic_ids2017")

    X = cic_bundle.frame[CANONICAL_FEATURES]
    y = cic_bundle.labels

    # NOTE: test_size=0.2 and random_state=42 are intentional constants.
    # train_verifier.py reproduces this exact split to avoid data leakage —
    # if you change these values here, you MUST update train_verifier.py too.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
    )

    # NOTE: test_size=0.2 and random_state=42 must match train_verifier.py UNSW split.
    unsw_test_bundle: DatasetBundle | None = None
    if unsw_path:
        unsw_bundle = load_dataset_bundle(unsw_path, "unsw_nb15_augmented")
        unsw_train_frame, unsw_test_frame, y_unsw_train, y_unsw_test = train_test_split(
            unsw_bundle.frame, unsw_bundle.labels, test_size=0.2, random_state=42, stratify=unsw_bundle.labels
        )
        X_train = pd.concat([X_train, unsw_train_frame[CANONICAL_FEATURES]], ignore_index=True)
        y_train = pd.concat([y_train, y_unsw_train], ignore_index=True)
        unsw_test_bundle = DatasetBundle(
            frame=unsw_test_frame.reset_index(drop=True),
            labels=y_unsw_test.reset_index(drop=True),
            dataset_name="unsw_nb15_held_out",
            source_files=unsw_bundle.source_files,
            dataset_audit=unsw_bundle.dataset_audit,
            rows_before_dedup=len(unsw_test_frame),
            rows_after_dedup=len(unsw_test_frame),
            merged_duplicates_removed=0,
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
            "model_version": "rf-flow-77-cic-unsw-v2",
            "feature_source": "backend/ml/artifacts/rf_ids_features.json",
            "features_count": len(CANONICAL_FEATURES),
            "train_datasets": ["CIC-IDS2017"] + (["UNSW-NB15"] if unsw_path else []),
        },
        "data_summary": {
            "cic_rows_before_dedup": int(cic_bundle.rows_before_dedup),
            "cic_rows_after_file_dedup": int(cic_bundle.rows_after_dedup),
            "cic_merged_duplicates_removed": int(cic_bundle.merged_duplicates_removed),
            "cic_rows_used_for_training": int(len(cic_bundle.frame)),
            "cic_binary_distribution": {
                str(key): int(value)
                for key, value in cic_bundle.labels.value_counts(dropna=False).sort_index().to_dict().items()
            },
            "cic_files": cic_bundle.dataset_audit,
        },
        "validation": metrics_from_predictions(y_val, val_pred, val_prob),
        "test": metrics_from_predictions(y_test, test_pred, test_prob),
        "train_rows": int(len(X_train)),
        "validation_rows": int(len(X_val)),
        "test_rows": int(len(X_test)),
    }

    if unsw_test_bundle is not None:
        results["cross_dataset"] = evaluate_bundle(pipeline, unsw_test_bundle)

    dump(pipeline, MODEL_PATH)

    # Keep rf_ids_features.json in sync with FEATURE_SCHEMA so that
    # _check_json_consistency() passes on the next import.
    FEATURES_PATH.write_text(json.dumps(list(CANONICAL_FEATURES), indent=2), encoding="utf-8")

    METRICS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    MODEL_INFO_PATH.write_text(
        json.dumps(
            {
                "model_name": "Random Forest",
                "model_version": "rf-flow-77-cic-unsw-v2",
                "feature_source": "backend/ml/artifacts/rf_ids_features.json",
                "features_count": len(CANONICAL_FEATURES),
                "features": CANONICAL_FEATURES,
                "train_datasets": ["CIC-IDS2017"] + (["UNSW-NB15"] if unsw_path else []),
                "primary_input_mode": "direct canonical 77-feature flow payload",
                "legacy_compatibility_mode": "simplified event payload mapped into the 77-feature schema with degraded approximation",
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
    parser = argparse.ArgumentParser(description="Train IDS Random Forest model on 77 canonical flow features.")
    parser.add_argument("--cic", required=True, help="Path to CIC-IDS2017 CSV file or directory")
    parser.add_argument("--unsw", required=False, help="Path to UNSW-NB15 CSV file or directory")
    args = parser.parse_args()

    results = train(args.cic, args.unsw)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
