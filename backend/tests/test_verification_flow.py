from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

TEMP_DIR = tempfile.TemporaryDirectory()
os.environ["REPORTS_DB_PATH"] = str(Path(TEMP_DIR.name) / "test_reports.db")

import server  # noqa: E402
from ml.schema import CANONICAL_FEATURES  # noqa: E402


class VerificationFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        server.app.testing = True
        cls.client = server.app.test_client()
        server.init_db()

    def test_analyze_returns_backend_verified_payload_and_persists(self) -> None:
        response = self.client.post(
            "/api/v1/analyze",
            data=json.dumps(
                {
                    "event": {
                        "id": "test-event-1",
                        "title": "Verification flow test",
                        "description": "Synthetic attack-like sample for end-to-end verification.",
                        "source_ip": "185.10.10.10",
                        "destination_ip": "10.0.0.5",
                        "source_port": 54000,
                        "destination_port": 22,
                        "protocol": "TCP",
                        "bytes_transferred_kb": 12000,
                        "duration_seconds": 4.0,
                        "packets_per_second": 920,
                        "failed_logins": 8,
                        "anomaly_score": 0.87,
                        "context_risk_score": 0.81,
                        "known_bad_source": True,
                        "off_hours_activity": True,
                        "repeated_attempts": True,
                    }
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        assert payload is not None

        for key in (
            "detector_label",
            "verification_confidence",
            "is_verified",
            "verification_details",
            "final_decision_status",
            "recommended_action",
            "feature_snapshot",
        ):
            self.assertIn(key, payload)

        conn = server.get_conn()
        row = conn.execute(
            "SELECT event_id, final_status, detector_output, verification_output FROM reports WHERE event_id = ?",
            ("test-event-1",),
        ).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["event_id"], "test-event-1")
        self.assertEqual(row["final_status"], payload["final_decision_status"])
        self.assertIsNotNone(row["detector_output"])
        self.assertIsNotNone(row["verification_output"])

    def test_analyze_accepts_direct_77_feature_payload(self) -> None:
        feature_payload = {
            feature_name: float(index + 1) for index, feature_name in enumerate(CANONICAL_FEATURES)
        }
        feature_payload["destination_port"] = 443.0

        response = self.client.post(
            "/api/v1/analyze",
            data=json.dumps(feature_payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        assert payload is not None
        self.assertIn("prediction", payload)
        self.assertIn("feature_snapshot", payload)
        self.assertEqual(
            payload["prediction"]["feature_snapshot"]["destination_port"],
            443.0,
        )


if __name__ == "__main__":
    unittest.main()
