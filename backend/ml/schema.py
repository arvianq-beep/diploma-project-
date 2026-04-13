from __future__ import annotations

import json
from pathlib import Path


ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = ARTIFACTS_DIR / "rf_ids_model.joblib"
METRICS_PATH = ARTIFACTS_DIR / "evaluation_metrics.json"
MODEL_INFO_PATH = ARTIFACTS_DIR / "model_info.json"
FEATURES_PATH = ARTIFACTS_DIR / "rf_ids_features.json"

DEFAULT_CANONICAL_FEATURES = [
    "ack_flag_count",
    "act_data_pkt_fwd",
    "active_max",
    "active_mean",
    "active_min",
    "active_std",
    "avg_bwd_segment_size",
    "avg_fwd_segment_size",
    "avg_packet_size",
    "bwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk",
    "bwd_avg_packets_bulk",
    "bwd_header_length",
    "bwd_iat_max",
    "bwd_iat_mean",
    "bwd_iat_min",
    "bwd_iat_std",
    "bwd_iat_total",
    "bwd_packet_length_max",
    "bwd_packet_length_mean",
    "bwd_packet_length_min",
    "bwd_packet_length_std",
    "bwd_packets_per_s",
    "bwd_psh_flags",
    "bwd_urg_flags",
    "cwr_flag_count",
    "destination_port",
    "down_up_ratio",
    "ece_flag_count",
    "fin_flag_count",
    "flow_bytes_per_s",
    "flow_duration",
    "flow_iat_max",
    "flow_iat_mean",
    "flow_iat_min",
    "flow_iat_std",
    "flow_packets_per_s",
    "fwd_avg_bulk_rate",
    "fwd_avg_bytes_bulk",
    "fwd_avg_packets_bulk",
    "fwd_header_length",
    "fwd_iat_max",
    "fwd_iat_mean",
    "fwd_iat_min",
    "fwd_iat_std",
    "fwd_iat_total",
    "fwd_packet_length_max",
    "fwd_packet_length_mean",
    "fwd_packet_length_min",
    "fwd_packet_length_std",
    "fwd_packets_per_s",
    "fwd_psh_flags",
    "fwd_urg_flags",
    "idle_max",
    "idle_mean",
    "idle_min",
    "idle_std",
    "init_win_bytes_backward",
    "init_win_bytes_forward",
    "min_seg_size_forward",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_min",
    "packet_length_std",
    "packet_length_variance",
    "psh_flag_count",
    "rst_flag_count",
    "subflow_bwd_bytes",
    "subflow_bwd_packets",
    "subflow_fwd_bytes",
    "subflow_fwd_packets",
    "syn_flag_count",
    "total_bwd_packets",
    "total_fwd_packets",
    "total_length_bwd_packets",
    "total_length_fwd_packets",
    "urg_flag_count",
]


def load_canonical_features() -> list[str]:
    """Load the exact model feature order from JSON source of truth."""

    if FEATURES_PATH.exists():
        try:
            payload = json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
            if isinstance(payload, list) and all(isinstance(item, str) for item in payload):
                return payload
        except Exception:
            pass
    return list(DEFAULT_CANONICAL_FEATURES)


CANONICAL_FEATURES = load_canonical_features()


def _aliases(*names: str) -> list[str]:
    return list(dict.fromkeys(names))


CIC_COLUMN_ALIASES = {
    "ack_flag_count": _aliases("ack_flag_count", "ACK Flag Count"),
    "act_data_pkt_fwd": _aliases("act_data_pkt_fwd", "act_data_pkt_fwd"),
    "active_max": _aliases("active_max", "Active Max"),
    "active_mean": _aliases("active_mean", "Active Mean"),
    "active_min": _aliases("active_min", "Active Min"),
    "active_std": _aliases("active_std", "Active Std"),
    "avg_bwd_segment_size": _aliases("avg_bwd_segment_size", "Avg Bwd Segment Size"),
    "avg_fwd_segment_size": _aliases("avg_fwd_segment_size", "Avg Fwd Segment Size"),
    "avg_packet_size": _aliases("avg_packet_size", "Average Packet Size"),
    "bwd_avg_bulk_rate": _aliases("bwd_avg_bulk_rate", "Bwd Avg Bulk Rate"),
    "bwd_avg_bytes_bulk": _aliases("bwd_avg_bytes_bulk", "Bwd Avg Bytes/Bulk"),
    "bwd_avg_packets_bulk": _aliases("bwd_avg_packets_bulk", "Bwd Avg Packets/Bulk"),
    "bwd_header_length": _aliases("bwd_header_length", "Bwd Header Length"),
    "bwd_iat_max": _aliases("bwd_iat_max", "Bwd IAT Max"),
    "bwd_iat_mean": _aliases("bwd_iat_mean", "Bwd IAT Mean"),
    "bwd_iat_min": _aliases("bwd_iat_min", "Bwd IAT Min"),
    "bwd_iat_std": _aliases("bwd_iat_std", "Bwd IAT Std"),
    "bwd_iat_total": _aliases("bwd_iat_total", "Bwd IAT Total"),
    "bwd_packet_length_max": _aliases("bwd_packet_length_max", "Bwd Packet Length Max"),
    "bwd_packet_length_mean": _aliases("bwd_packet_length_mean", "Bwd Packet Length Mean"),
    "bwd_packet_length_min": _aliases("bwd_packet_length_min", "Bwd Packet Length Min"),
    "bwd_packet_length_std": _aliases("bwd_packet_length_std", "Bwd Packet Length Std"),
    "bwd_packets_per_s": _aliases("bwd_packets_per_s", "Bwd Packets/s"),
    "bwd_psh_flags": _aliases("bwd_psh_flags", "Bwd PSH Flags"),
    "bwd_urg_flags": _aliases("bwd_urg_flags", "Bwd URG Flags"),
    "cwr_flag_count": _aliases("cwr_flag_count", "CWR Flag Count", "CWE Flag Count"),
    "destination_port": _aliases("destination_port", "Destination Port", "Dst Port", "dsport"),
    "down_up_ratio": _aliases("down_up_ratio", "Down/Up Ratio"),
    "ece_flag_count": _aliases("ece_flag_count", "ECE Flag Count"),
    "fin_flag_count": _aliases("fin_flag_count", "FIN Flag Count"),
    "flow_bytes_per_s": _aliases("flow_bytes_per_s", "Flow Bytes/s", "Flow Byts/s"),
    "flow_duration": _aliases("flow_duration", "Flow Duration", "duration", "dur"),
    "flow_iat_max": _aliases("flow_iat_max", "Flow IAT Max"),
    "flow_iat_mean": _aliases("flow_iat_mean", "Flow IAT Mean"),
    "flow_iat_min": _aliases("flow_iat_min", "Flow IAT Min"),
    "flow_iat_std": _aliases("flow_iat_std", "Flow IAT Std"),
    "flow_packets_per_s": _aliases("flow_packets_per_s", "Flow Packets/s", "Flow Pkts/s", "rate"),
    "fwd_avg_bulk_rate": _aliases("fwd_avg_bulk_rate", "Fwd Avg Bulk Rate"),
    "fwd_avg_bytes_bulk": _aliases("fwd_avg_bytes_bulk", "Fwd Avg Bytes/Bulk"),
    "fwd_avg_packets_bulk": _aliases("fwd_avg_packets_bulk", "Fwd Avg Packets/Bulk"),
    "fwd_header_length": _aliases("fwd_header_length", "Fwd Header Length", "Fwd Header Length.1"),
    "fwd_iat_max": _aliases("fwd_iat_max", "Fwd IAT Max"),
    "fwd_iat_mean": _aliases("fwd_iat_mean", "Fwd IAT Mean"),
    "fwd_iat_min": _aliases("fwd_iat_min", "Fwd IAT Min"),
    "fwd_iat_std": _aliases("fwd_iat_std", "Fwd IAT Std"),
    "fwd_iat_total": _aliases("fwd_iat_total", "Fwd IAT Total"),
    "fwd_packet_length_max": _aliases("fwd_packet_length_max", "Fwd Packet Length Max"),
    "fwd_packet_length_mean": _aliases("fwd_packet_length_mean", "Fwd Packet Length Mean"),
    "fwd_packet_length_min": _aliases("fwd_packet_length_min", "Fwd Packet Length Min"),
    "fwd_packet_length_std": _aliases("fwd_packet_length_std", "Fwd Packet Length Std"),
    "fwd_packets_per_s": _aliases("fwd_packets_per_s", "Fwd Packets/s"),
    "fwd_psh_flags": _aliases("fwd_psh_flags", "Fwd PSH Flags"),
    "fwd_urg_flags": _aliases("fwd_urg_flags", "Fwd URG Flags"),
    "idle_max": _aliases("idle_max", "Idle Max"),
    "idle_mean": _aliases("idle_mean", "Idle Mean"),
    "idle_min": _aliases("idle_min", "Idle Min"),
    "idle_std": _aliases("idle_std", "Idle Std"),
    "init_win_bytes_backward": _aliases("init_win_bytes_backward", "Init_Win_bytes_backward"),
    "init_win_bytes_forward": _aliases("init_win_bytes_forward", "Init_Win_bytes_forward"),
    "min_seg_size_forward": _aliases("min_seg_size_forward", "min_seg_size_forward"),
    "packet_length_max": _aliases("packet_length_max", "Max Packet Length"),
    "packet_length_mean": _aliases("packet_length_mean", "Packet Length Mean"),
    "packet_length_min": _aliases("packet_length_min", "Min Packet Length"),
    "packet_length_std": _aliases("packet_length_std", "Packet Length Std"),
    "packet_length_variance": _aliases("packet_length_variance", "Packet Length Variance"),
    "psh_flag_count": _aliases("psh_flag_count", "PSH Flag Count"),
    "rst_flag_count": _aliases("rst_flag_count", "RST Flag Count"),
    "subflow_bwd_bytes": _aliases("subflow_bwd_bytes", "Subflow Bwd Bytes"),
    "subflow_bwd_packets": _aliases("subflow_bwd_packets", "Subflow Bwd Packets"),
    "subflow_fwd_bytes": _aliases("subflow_fwd_bytes", "Subflow Fwd Bytes"),
    "subflow_fwd_packets": _aliases("subflow_fwd_packets", "Subflow Fwd Packets"),
    "syn_flag_count": _aliases("syn_flag_count", "SYN Flag Count"),
    "total_bwd_packets": _aliases("total_bwd_packets", "Total Backward Packets", "Tot Bwd Pkts"),
    "total_fwd_packets": _aliases("total_fwd_packets", "Total Fwd Packets", "Tot Fwd Pkts"),
    "total_length_bwd_packets": _aliases("total_length_bwd_packets", "Total Length of Bwd Packets", "TotLen Bwd Pkts"),
    "total_length_fwd_packets": _aliases("total_length_fwd_packets", "Total Length of Fwd Packets", "TotLen Fwd Pkts"),
    "urg_flag_count": _aliases("urg_flag_count", "URG Flag Count"),
}

UNSW_COLUMN_ALIASES = {
    feature_name: _aliases(
        feature_name,
        *([CIC_COLUMN_ALIASES[feature_name][1]] if len(CIC_COLUMN_ALIASES[feature_name]) > 1 else []),
    )
    for feature_name in CANONICAL_FEATURES
}
