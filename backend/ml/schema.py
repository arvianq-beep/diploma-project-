from __future__ import annotations

from pathlib import Path


ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = ARTIFACTS_DIR / "rf_ids_model.joblib"
METRICS_PATH = ARTIFACTS_DIR / "evaluation_metrics.json"
MODEL_INFO_PATH = ARTIFACTS_DIR / "model_info.json"

CANONICAL_FEATURES = [
    "protocol",
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

CIC_COLUMN_ALIASES = {
    "protocol": ["Protocol", "protocol"],
    "source_port": ["Src Port", "Source Port", "src_port", "sport"],
    "destination_port": ["Destination Port", "Dst Port", "dst_port", "dsport"],
    "duration": ["Flow Duration", "duration", "dur"],
    "forward_packets": ["Tot Fwd Pkts", "Total Fwd Packets", "tot_fwd_pkts", "spkts"],
    "backward_packets": ["Tot Bwd Pkts", "Total Backward Packets", "tot_bwd_pkts", "dpkts"],
    "forward_bytes": ["TotLen Fwd Pkts", "Total Length of Fwd Packets", "totlen_fwd_pkts", "sbytes"],
    "backward_bytes": ["TotLen Bwd Pkts", "Total Length of Bwd Packets", "totlen_bwd_pkts", "dbytes"],
    "bytes_per_second": ["Flow Bytes/s", "flow_bytes_s", "bytes_per_second"],
    "packets_per_second": ["Flow Packets/s", "flow_packets_s", "packets_per_second", "rate"],
}

UNSW_COLUMN_ALIASES = {
    "protocol": ["proto", "protocol"],
    "source_port": ["sport", "src_port", "Source Port"],
    "destination_port": ["dsport", "dst_port", "Destination Port"],
    "duration": ["dur", "duration", "Flow Duration"],
    "forward_packets": ["spkts", "Tot Fwd Pkts"],
    "backward_packets": ["dpkts", "Tot Bwd Pkts"],
    "forward_bytes": ["sbytes", "TotLen Fwd Pkts"],
    "backward_bytes": ["dbytes", "TotLen Bwd Pkts"],
    "bytes_per_second": ["bytes_per_second", "Flow Bytes/s"],
    "packets_per_second": ["rate", "Flow Packets/s", "packets_per_second"],
}
