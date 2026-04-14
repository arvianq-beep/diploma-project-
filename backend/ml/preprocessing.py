from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from .schema import CANONICAL_FEATURES, CIC_COLUMN_ALIASES, UNSW_COLUMN_ALIASES


@dataclass
class DatasetBundle:
    frame: pd.DataFrame
    labels: pd.Series
    dataset_name: str
    source_files: list[str]
    dataset_audit: list[dict]
    rows_before_dedup: int
    rows_after_dedup: int
    merged_duplicates_removed: int


def _find_column(columns: Iterable[str], aliases: list[str]) -> str | None:
    normalized = {column.strip().lower(): column for column in columns}
    for alias in aliases:
        match = normalized.get(alias.strip().lower())
        if match:
            return match
    return None


def _coerce_numeric(series: pd.Series) -> pd.Series:
    clean = series.replace([np.inf, -np.inf], np.nan)
    return pd.to_numeric(clean, errors="coerce")


def _empty_series(length: int, fill_value: float = 0.0) -> pd.Series:
    return pd.Series([fill_value] * length)


def _clean_frame(frame: pd.DataFrame) -> pd.DataFrame:
    cleaned = frame.copy()
    cleaned.columns = [str(column).strip() for column in cleaned.columns]
    return cleaned.replace([np.inf, -np.inf], np.nan)


def _label_to_binary(series: pd.Series) -> pd.Series:
    def normalize(value) -> int:
        if pd.isna(value):
            return 0
        if isinstance(value, (int, float, np.integer, np.floating)):
            return 1 if float(value) > 0 else 0
        text = str(value).strip().lower()
        if text in {"0", "normal", "benign", "benign traffic"}:
            return 0
        return 1

    return series.apply(normalize).astype(int)


def harmonize_frame(frame: pd.DataFrame, dataset_name: str) -> pd.DataFrame:
    """Map raw dataset columns onto the 77 canonical feature names.

    All 77 features are numeric.  Any feature whose source column cannot be
    found in the raw frame is filled with 0.0.
    """
    frame = _clean_frame(frame)
    aliases = CIC_COLUMN_ALIASES if dataset_name == "cic_ids2017" else UNSW_COLUMN_ALIASES
    length = len(frame)
    output = pd.DataFrame(index=frame.index)

    for feature in CANONICAL_FEATURES:
        feature_aliases = aliases.get(feature, [feature])
        source_column = _find_column(frame.columns, feature_aliases)
        if source_column is None:
            output[feature] = _empty_series(length)
        else:
            output[feature] = _coerce_numeric(frame[source_column])

    # CIC-IDS2017 stores Flow Duration in microseconds; convert to seconds so
    # all time-based features share the same unit at inference time.
    if dataset_name == "cic_ids2017":
        output["flow_duration"] = output["flow_duration"] / 1_000_000.0

    # Clip and fill per-feature constraints.
    output["flow_duration"] = output["flow_duration"].fillna(0.0).clip(lower=0.0)
    output["destination_port"] = (
        output["destination_port"].fillna(0).clip(lower=0, upper=65535)
    )

    # All remaining features must be non-negative.
    for feature in CANONICAL_FEATURES:
        if feature not in {"flow_duration", "destination_port"}:
            output[feature] = output[feature].fillna(0.0).clip(lower=0.0)

    return output[CANONICAL_FEATURES]


def load_dataset_bundle(dataset_dir: str | Path, dataset_name: str) -> DatasetBundle:
    path = Path(dataset_dir)
    if not path.exists():
        raise FileNotFoundError(f"Dataset path not found: {path}")

    csv_files = sorted(path.rglob("*.csv")) if path.is_dir() else [path]
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {path}")

    frames: list[pd.DataFrame] = []
    labels: list[pd.Series] = []
    source_files: list[str] = []
    dataset_audit: list[dict] = []
    rows_before_dedup = 0
    rows_after_dedup = 0

    for csv_path in csv_files:
        raw_frame = pd.read_csv(csv_path, low_memory=False)
        frame = raw_frame.copy()
        frame.columns = [str(column).strip() for column in frame.columns]
        numeric_part = frame.select_dtypes(include=[np.number])
        inf_values = int(np.isinf(numeric_part.to_numpy()).sum()) if not numeric_part.empty else 0
        missing_before = int(frame.isna().sum().sum())
        duplicate_rows = int(frame.duplicated().sum())
        rows_before_dedup += int(len(frame))

        frame = frame.replace([np.inf, -np.inf], np.nan)
        missing_after_inf = int(frame.isna().sum().sum())
        frame = frame.drop_duplicates().reset_index(drop=True)
        rows_after_dedup += int(len(frame))

        label_column = _find_column(
            frame.columns,
            ["Label", "label", "attack_cat", "attack_cat ", "attack"],
        )
        if label_column is None and "label" in frame.columns:
            label_column = "label"
        if label_column is None:
            raise ValueError(f"Label column not found in {csv_path}")

        binary_labels = _label_to_binary(frame[label_column])
        frames.append(harmonize_frame(frame, dataset_name))
        labels.append(binary_labels)
        source_files.append(csv_path.name)
        dataset_audit.append(
            {
                "file": csv_path.name,
                "rows": int(len(raw_frame)),
                "rows_after_dedup": int(len(frame)),
                "columns": [str(column).strip() for column in raw_frame.columns],
                "label_column": label_column,
                "missing_values_before_cleaning": missing_before,
                "missing_values_after_inf_replacement": missing_after_inf,
                "inf_values": inf_values,
                "duplicate_rows_removed": duplicate_rows,
                "raw_label_distribution": (
                    frame[label_column]
                    .astype(str)
                    .str.strip()
                    .value_counts(dropna=False)
                    .to_dict()
                ),
                "binary_label_distribution": {
                    str(key): int(value)
                    for key, value in binary_labels.value_counts(dropna=False)
                    .sort_index()
                    .to_dict()
                    .items()
                },
            }
        )

    merged_frame = pd.concat(frames, ignore_index=True)
    merged_labels = pd.concat(labels, ignore_index=True)
    merged = merged_frame.copy()
    merged["_target"] = merged_labels.to_numpy()
    merged_duplicates_removed = int(merged.duplicated().sum())
    if merged_duplicates_removed:
        merged = merged.drop_duplicates().reset_index(drop=True)
    merged_labels = merged.pop("_target").astype(int)
    merged_frame = merged

    return DatasetBundle(
        frame=merged_frame,
        labels=merged_labels,
        dataset_name=dataset_name,
        source_files=source_files,
        dataset_audit=dataset_audit,
        rows_before_dedup=rows_before_dedup,
        rows_after_dedup=rows_after_dedup,
        merged_duplicates_removed=merged_duplicates_removed,
    )
