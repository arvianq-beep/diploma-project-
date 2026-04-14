from __future__ import annotations

import json
from pathlib import Path


ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = ARTIFACTS_DIR / "rf_ids_model.joblib"
METRICS_PATH = ARTIFACTS_DIR / "evaluation_metrics.json"
MODEL_INFO_PATH = ARTIFACTS_DIR / "model_info.json"
FEATURES_PATH = ARTIFACTS_DIR / "rf_ids_features.json"


def _load_canonical_features() -> list[str]:
    """Load the canonical 77-feature list from rf_ids_features.json.

    Falls back to a hardcoded copy of the same list so the module works even
    when the artifacts directory has not been populated yet.
    """
    if FEATURES_PATH.exists():
        try:
            return json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    # Fallback: identical content to rf_ids_features.json.
    return [
        "ack_flag_count", "act_data_pkt_fwd", "active_max", "active_mean",
        "active_min", "active_std", "avg_bwd_segment_size", "avg_fwd_segment_size",
        "avg_packet_size", "bwd_avg_bulk_rate", "bwd_avg_bytes_bulk",
        "bwd_avg_packets_bulk", "bwd_header_length", "bwd_iat_max", "bwd_iat_mean",
        "bwd_iat_min", "bwd_iat_std", "bwd_iat_total", "bwd_packet_length_max",
        "bwd_packet_length_mean", "bwd_packet_length_min", "bwd_packet_length_std",
        "bwd_packets_per_s", "bwd_psh_flags", "bwd_urg_flags", "cwr_flag_count",
        "destination_port", "down_up_ratio", "ece_flag_count", "fin_flag_count",
        "flow_bytes_per_s", "flow_duration", "flow_iat_max", "flow_iat_mean",
        "flow_iat_min", "flow_iat_std", "flow_packets_per_s", "fwd_avg_bulk_rate",
        "fwd_avg_bytes_bulk", "fwd_avg_packets_bulk", "fwd_header_length",
        "fwd_iat_max", "fwd_iat_mean", "fwd_iat_min", "fwd_iat_std", "fwd_iat_total",
        "fwd_packet_length_max", "fwd_packet_length_mean", "fwd_packet_length_min",
        "fwd_packet_length_std", "fwd_packets_per_s", "fwd_psh_flags", "fwd_urg_flags",
        "idle_max", "idle_mean", "idle_min", "idle_std", "init_win_bytes_backward",
        "init_win_bytes_forward", "min_seg_size_forward", "packet_length_max",
        "packet_length_mean", "packet_length_min", "packet_length_std",
        "packet_length_variance", "psh_flag_count", "rst_flag_count",
        "subflow_bwd_bytes", "subflow_bwd_packets", "subflow_fwd_bytes",
        "subflow_fwd_packets", "syn_flag_count", "total_bwd_packets",
        "total_fwd_packets", "total_length_bwd_packets", "total_length_fwd_packets",
        "urg_flag_count",
    ]


# Single source of truth: 77 canonical flow feature names in strict order.
CANONICAL_FEATURES: list[str] = _load_canonical_features()

# ---------------------------------------------------------------------------
# CIC-IDS2017 raw column → canonical feature name aliases.
# The resolver tries each alias in order and picks the first match.
# ---------------------------------------------------------------------------
CIC_COLUMN_ALIASES: dict[str, list[str]] = {
    "ack_flag_count":           ["ACK Flag Count", "ack_flag_count"],
    "act_data_pkt_fwd":         ["act_data_pkt_fwd"],
    "active_max":               ["Active Max", "active_max"],
    "active_mean":              ["Active Mean", "active_mean"],
    "active_min":               ["Active Min", "active_min"],
    "active_std":               ["Active Std", "active_std"],
    "avg_bwd_segment_size":     ["Avg Bwd Segment Size", "avg_bwd_segment_size"],
    "avg_fwd_segment_size":     ["Avg Fwd Segment Size", "avg_fwd_segment_size"],
    "avg_packet_size":          ["Average Packet Size", "Avg Pkt Size", "avg_packet_size"],
    "bwd_avg_bulk_rate":        ["Bwd Avg Bulk Rate", "bwd_avg_bulk_rate"],
    "bwd_avg_bytes_bulk":       ["Bwd Avg Bytes/Bulk", "bwd_avg_bytes_bulk"],
    "bwd_avg_packets_bulk":     ["Bwd Avg Packets/Bulk", "bwd_avg_packets_bulk"],
    "bwd_header_length":        ["Bwd Header Length", "bwd_header_length"],
    "bwd_iat_max":              ["Bwd IAT Max", "bwd_iat_max"],
    "bwd_iat_mean":             ["Bwd IAT Mean", "bwd_iat_mean"],
    "bwd_iat_min":              ["Bwd IAT Min", "bwd_iat_min"],
    "bwd_iat_std":              ["Bwd IAT Std", "bwd_iat_std"],
    "bwd_iat_total":            ["Bwd IAT Total", "bwd_iat_total"],
    "bwd_packet_length_max":    ["Bwd Packet Length Max", "bwd_packet_length_max"],
    "bwd_packet_length_mean":   ["Bwd Packet Length Mean", "bwd_packet_length_mean"],
    "bwd_packet_length_min":    ["Bwd Packet Length Min", "bwd_packet_length_min"],
    "bwd_packet_length_std":    ["Bwd Packet Length Std", "bwd_packet_length_std"],
    "bwd_packets_per_s":        ["Bwd Packets/s", "Bwd Pkts/s", "bwd_packets_per_s"],
    "bwd_psh_flags":            ["Bwd PSH Flags", "bwd_psh_flags"],
    "bwd_urg_flags":            ["Bwd URG Flags", "bwd_urg_flags"],
    # CIC labels this "CWE Flag Count" but the canonical name follows RFC convention (CWR).
    "cwr_flag_count":           ["CWE Flag Count", "CWR Flag Count", "cwr_flag_count"],
    "destination_port":         ["Destination Port", "Dst Port", "dst_port", "destination_port"],
    "down_up_ratio":            ["Down/Up Ratio", "down_up_ratio"],
    "ece_flag_count":           ["ECE Flag Count", "ece_flag_count"],
    "fin_flag_count":           ["FIN Flag Count", "fin_flag_count"],
    "flow_bytes_per_s":         ["Flow Bytes/s", "Flow Byts/s", "flow_bytes_per_s", "bytes_per_second"],
    "flow_duration":            ["Flow Duration", "flow_duration", "duration", "dur"],
    "flow_iat_max":             ["Flow IAT Max", "flow_iat_max"],
    "flow_iat_mean":            ["Flow IAT Mean", "flow_iat_mean"],
    "flow_iat_min":             ["Flow IAT Min", "flow_iat_min"],
    "flow_iat_std":             ["Flow IAT Std", "flow_iat_std"],
    "flow_packets_per_s":       ["Flow Packets/s", "Flow Pkts/s", "flow_packets_per_s", "packets_per_second", "rate"],
    "fwd_avg_bulk_rate":        ["Fwd Avg Bulk Rate", "fwd_avg_bulk_rate"],
    "fwd_avg_bytes_bulk":       ["Fwd Avg Bytes/Bulk", "fwd_avg_bytes_bulk"],
    "fwd_avg_packets_bulk":     ["Fwd Avg Packets/Bulk", "fwd_avg_packets_bulk"],
    # CIC contains "Fwd Header Length" and a duplicate "Fwd Header Length.1"; both map here.
    "fwd_header_length":        ["Fwd Header Length", "Fwd Header Length.1", "fwd_header_length"],
    "fwd_iat_max":              ["Fwd IAT Max", "fwd_iat_max"],
    "fwd_iat_mean":             ["Fwd IAT Mean", "fwd_iat_mean"],
    "fwd_iat_min":              ["Fwd IAT Min", "fwd_iat_min"],
    "fwd_iat_std":              ["Fwd IAT Std", "fwd_iat_std"],
    "fwd_iat_total":            ["Fwd IAT Total", "fwd_iat_total"],
    "fwd_packet_length_max":    ["Fwd Packet Length Max", "fwd_packet_length_max"],
    "fwd_packet_length_mean":   ["Fwd Packet Length Mean", "fwd_packet_length_mean"],
    "fwd_packet_length_min":    ["Fwd Packet Length Min", "fwd_packet_length_min"],
    "fwd_packet_length_std":    ["Fwd Packet Length Std", "fwd_packet_length_std"],
    "fwd_packets_per_s":        ["Fwd Packets/s", "Fwd Pkts/s", "fwd_packets_per_s"],
    "fwd_psh_flags":            ["Fwd PSH Flags", "fwd_psh_flags"],
    "fwd_urg_flags":            ["Fwd URG Flags", "fwd_urg_flags"],
    "idle_max":                 ["Idle Max", "idle_max"],
    "idle_mean":                ["Idle Mean", "idle_mean"],
    "idle_min":                 ["Idle Min", "idle_min"],
    "idle_std":                 ["Idle Std", "idle_std"],
    "init_win_bytes_backward":  ["Init_Win_bytes_backward", "init_win_bytes_backward"],
    "init_win_bytes_forward":   ["Init_Win_bytes_forward", "init_win_bytes_forward"],
    "min_seg_size_forward":     ["min_seg_size_forward"],
    "packet_length_max":        ["Max Packet Length", "Packet Length Max", "packet_length_max"],
    "packet_length_mean":       ["Packet Length Mean", "packet_length_mean"],
    "packet_length_min":        ["Min Packet Length", "Packet Length Min", "packet_length_min"],
    "packet_length_std":        ["Packet Length Std", "packet_length_std"],
    "packet_length_variance":   ["Packet Length Variance", "packet_length_variance"],
    "psh_flag_count":           ["PSH Flag Count", "psh_flag_count"],
    "rst_flag_count":           ["RST Flag Count", "rst_flag_count"],
    "subflow_bwd_bytes":        ["Subflow Bwd Bytes", "subflow_bwd_bytes"],
    "subflow_bwd_packets":      ["Subflow Bwd Packets", "subflow_bwd_packets"],
    "subflow_fwd_bytes":        ["Subflow Fwd Bytes", "subflow_fwd_bytes"],
    "subflow_fwd_packets":      ["Subflow Fwd Packets", "subflow_fwd_packets"],
    "syn_flag_count":           ["SYN Flag Count", "syn_flag_count"],
    "total_bwd_packets":        ["Total Backward Packets", "Tot Bwd Pkts", "total_bwd_packets", "dpkts"],
    "total_fwd_packets":        ["Total Fwd Packets", "Tot Fwd Pkts", "total_fwd_packets", "spkts"],
    "total_length_bwd_packets": ["Total Length of Bwd Packets", "TotLen Bwd Pkts", "total_length_bwd_packets", "dbytes"],
    "total_length_fwd_packets": ["Total Length of Fwd Packets", "TotLen Fwd Pkts", "total_length_fwd_packets", "sbytes"],
    "urg_flag_count":           ["URG Flag Count", "urg_flag_count"],
}

# ---------------------------------------------------------------------------
# UNSW-NB15 best-effort column aliases for features that have close
# equivalents.  Features not listed here will default to 0.0 when a UNSW
# dataset is harmonised.
# ---------------------------------------------------------------------------
UNSW_COLUMN_ALIASES: dict[str, list[str]] = {
    "destination_port":         ["dsport", "Destination Port", "dst_port"],
    "flow_duration":            ["dur", "duration", "Flow Duration"],
    "total_fwd_packets":        ["spkts", "Tot Fwd Pkts"],
    "total_bwd_packets":        ["dpkts", "Tot Bwd Pkts"],
    "total_length_fwd_packets": ["sbytes", "TotLen Fwd Pkts"],
    "total_length_bwd_packets": ["dbytes", "TotLen Bwd Pkts"],
    "flow_bytes_per_s":         ["bytes_per_second", "Flow Bytes/s"],
    "flow_packets_per_s":       ["rate", "Flow Packets/s", "packets_per_second"],
    "fwd_packets_per_s":        ["Fwd Packets/s"],
    "bwd_packets_per_s":        ["Bwd Packets/s"],
    "syn_flag_count":           ["SYN Flag Count"],
    "fin_flag_count":           ["FIN Flag Count"],
    "rst_flag_count":           ["RST Flag Count"],
    "ack_flag_count":           ["ACK Flag Count"],
}
