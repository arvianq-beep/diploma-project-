from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.inference import MLPredictor  # noqa: E402
from ml.schema import CANONICAL_FEATURES  # noqa: E402


class _CapturePipeline:
    def __init__(self):
        self.feature_names_in_ = np.asarray(CANONICAL_FEATURES)
        self.last_frame = None

    def predict_proba(self, frame):
        self.last_frame = frame.copy()
        return np.asarray([[0.18, 0.82]], dtype=float)


class PredictorInferenceTest(unittest.TestCase):
    def _temp_metadata(self) -> tuple[tempfile.TemporaryDirectory, Path, Path, Path]:
        temp_dir = tempfile.TemporaryDirectory()
        temp_path = Path(temp_dir.name)
        model_path = temp_path / "rf_ids_model.joblib"
        model_path.write_bytes(b"placeholder")
        model_info_path = temp_path / "model_info.json"
        metrics_path = temp_path / "evaluation_metrics.json"
        model_info_path.write_text(
            json.dumps(
                {
                    "model_name": "Random Forest",
                    "model_version": "rf-flow-77-cic-unsw-v2",
                    "features_count": len(CANONICAL_FEATURES),
                }
            ),
            encoding="utf-8",
        )
        metrics_path.write_text(json.dumps({"status": "ok"}), encoding="utf-8")
        return temp_dir, model_path, model_info_path, metrics_path

    def test_predictor_accepts_full_77_feature_payload(self) -> None:
        temp_dir, model_path, model_info_path, metrics_path = self._temp_metadata()
        pipeline = _CapturePipeline()
        payload = {
            feature_name: float(index + 1) for index, feature_name in enumerate(CANONICAL_FEATURES)
        }
        payload["destination_port"] = 443.0

        try:
            with patch("ml.inference.load", return_value=pipeline):
                predictor = MLPredictor(
                    model_path=model_path,
                    model_info_path=model_info_path,
                    metrics_path=metrics_path,
                )

            result = predictor.predict_from_features(payload)
            self.assertEqual(result.label, "Attack")
            self.assertGreater(result.confidence, 0.5)
            self.assertEqual(list(pipeline.last_frame.columns), CANONICAL_FEATURES)
            self.assertEqual(len(result.feature_snapshot), len(CANONICAL_FEATURES))
        finally:
            temp_dir.cleanup()

    def test_predictor_accepts_legacy_payload_in_compatibility_mode(self) -> None:
        predictor = MLPredictor(model_path="missing-model.joblib")
        result = predictor.predict_from_event(
            {
                "destination_port": 22,
                "duration_seconds": 4.0,
                "packets_per_second": 900.0,
                "bytes_per_second": 320000.0,
                "forward_packets": 1800.0,
                "backward_packets": 1200.0,
                "forward_bytes": 900000.0,
                "backward_bytes": 320000.0,
                "known_bad_source": True,
                "failed_logins": 8,
                "repeated_attempts": True,
            }
        )

        self.assertIn(result.label, {"Attack", "Benign"})
        self.assertEqual(result.feature_snapshot["destination_port"], 22.0)
        self.assertEqual(result.feature_snapshot["flow_duration"], 4.0)
        self.assertEqual(result.feature_snapshot["flow_packets_per_s"], 900.0)
        self.assertEqual(result.feature_snapshot["total_fwd_packets"], 1800.0)
        self.assertEqual(result.feature_snapshot["total_length_bwd_packets"], 320000.0)

    def test_dataframe_order_matches_rf_ids_features_json(self) -> None:
        temp_dir, model_path, model_info_path, metrics_path = self._temp_metadata()
        pipeline = _CapturePipeline()

        try:
            with patch("ml.inference.load", return_value=pipeline):
                predictor = MLPredictor(
                    model_path=model_path,
                    model_info_path=model_info_path,
                    metrics_path=metrics_path,
                )

            predictor.predict_from_features({"flow_duration": 12.0, "destination_port": 8080})
            assert pipeline.last_frame is not None
            self.assertEqual(list(pipeline.last_frame.columns), CANONICAL_FEATURES)
            self.assertEqual(pipeline.last_frame.shape[1], 77)
        finally:
            temp_dir.cleanup()

    def test_missing_optional_fields_do_not_crash(self) -> None:
        predictor = MLPredictor(model_path="missing-model.joblib")
        result = predictor.predict_from_features({"destination_port": 80.0})

        self.assertIn(result.label, {"Attack", "Benign"})
        self.assertEqual(result.feature_snapshot["destination_port"], 80.0)
        self.assertEqual(result.feature_snapshot["flow_duration"], 0.0)

    def test_model_version_reads_updated_model_info(self) -> None:
        temp_dir, model_path, model_info_path, metrics_path = self._temp_metadata()
        pipeline = _CapturePipeline()

        try:
            with patch("ml.inference.load", return_value=pipeline):
                predictor = MLPredictor(
                    model_path=model_path,
                    model_info_path=model_info_path,
                    metrics_path=metrics_path,
                )
            self.assertEqual(predictor.model_version, "rf-flow-77-cic-unsw-v2")
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
