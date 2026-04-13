"""Network flow aggregation and 77-feature extraction.

Packet → flow aggregation uses a 5-tuple key (src_ip, dst_ip, src_port,
dst_port, proto).  A flow is considered complete when:
  - TCP FIN or RST flag is seen
  - 30 s idle timeout elapses since the last packet
  - MAX_PACKETS_PER_FLOW packets have been accumulated

Feature units are aligned with CIC-IDS2017 training data:
  - flow_duration   → seconds   (float)
  - IAT features    → microseconds (float)  [CIC exports μs]
  - active/idle     → microseconds (float)
  - byte/packet counts → raw integer values cast to float
"""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FLOW_TIMEOUT_S: float = 30.0          # idle timeout → force-complete the flow
MAX_PACKETS_PER_FLOW: int = 10_000    # hard cap to avoid unbounded memory


# ---------------------------------------------------------------------------
# Raw packet representation (capture-source agnostic)
# ---------------------------------------------------------------------------
@dataclass
class RawPacket:
    """Minimal packet representation produced by any capture source."""

    timestamp: float            # Unix epoch seconds (float)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int                  # IANA protocol number: 6=TCP, 17=UDP, 1=ICMP
    length: int                 # total IP packet length in bytes
    payload_length: int         # IP payload (transport header + data), bytes
    ip_header_length: int       # IP header length in bytes (default 20)
    tcp_flags: int = 0          # bitmask: FIN=0x01, SYN=0x02, RST=0x04,
                                #          PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80
    tcp_window: int = 0         # TCP receive window size in bytes
    direction: str = "fwd"      # "fwd" or "bwd" (resolved by FlowAggregator)


# ---------------------------------------------------------------------------
# Internal stored-packet container (direction + timing already resolved)
# ---------------------------------------------------------------------------
@dataclass
class _StoredPkt:
    ts: float
    length: int
    payload_length: int
    header_length: int
    direction: str      # "fwd" or "bwd"
    tcp_flags: int
    tcp_window: int


# ---------------------------------------------------------------------------
# FlowRecord — accumulates packets and produces the 77-feature dict
# ---------------------------------------------------------------------------
class FlowRecord:
    """Stateful per-flow accumulator."""

    def __init__(self, key: tuple, first_pkt: RawPacket) -> None:
        self.key = key          # (src_ip, dst_ip, src_port, dst_port, proto)
        self._pkts: list[_StoredPkt] = []
        self._init_win_fwd: int = -1
        self._init_win_bwd: int = -1
        self.complete: bool = False
        self._add(first_pkt, direction="fwd")

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------
    def add_packet(self, pkt: RawPacket, direction: str) -> None:
        """Append a packet in the specified direction and check completion."""
        self._add(pkt, direction)
        if direction == "fwd" and self._init_win_fwd < 0:
            self._init_win_fwd = pkt.tcp_window
        elif direction == "bwd" and self._init_win_bwd < 0:
            self._init_win_bwd = pkt.tcp_window
        flags = pkt.tcp_flags
        if flags & 0x05:  # FIN(0x01) or RST(0x04)
            self.complete = True
        if len(self._pkts) >= MAX_PACKETS_PER_FLOW:
            self.complete = True

    def last_seen(self) -> float:
        return self._pkts[-1].ts if self._pkts else 0.0

    def extract_features(self) -> dict[str, float]:
        """Return the 77-feature dict aligned with FEATURE_SCHEMA / CIC-IDS2017."""
        return extract_canonical_features(
            self._pkts,
            self.key,
            self._init_win_fwd,
            self._init_win_bwd,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _add(self, pkt: RawPacket, direction: str) -> None:
        self._pkts.append(
            _StoredPkt(
                ts=pkt.timestamp,
                length=pkt.length,
                payload_length=pkt.payload_length,
                header_length=pkt.ip_header_length,
                direction=direction,
                tcp_flags=pkt.tcp_flags,
                tcp_window=pkt.tcp_window,
            )
        )


# ---------------------------------------------------------------------------
# FlowAggregator — maps packets to FlowRecord instances
# ---------------------------------------------------------------------------
class FlowAggregator:
    """Routes incoming packets to the appropriate FlowRecord.

    Completed flows are collected in `self.completed` and removed from the
    active table.  Call `flush_timeouts()` periodically to expire idle flows.
    """

    def __init__(
        self,
        timeout_s: float = FLOW_TIMEOUT_S,
        max_per_flow: int = MAX_PACKETS_PER_FLOW,
    ) -> None:
        self.timeout_s = timeout_s
        self.max_per_flow = max_per_flow
        self._flows: dict[tuple, FlowRecord] = {}
        self.completed: list[FlowRecord] = []

    def ingest(self, pkt: RawPacket) -> None:
        """Add a packet; completed flows are moved to self.completed."""
        key_fwd = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto)
        key_bwd = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.proto)

        if key_fwd in self._flows:
            key, direction = key_fwd, "fwd"
        elif key_bwd in self._flows:
            key, direction = key_bwd, "bwd"
        else:
            # New flow — always treat first packet as forward
            key, direction = key_fwd, "fwd"
            self._flows[key] = FlowRecord(key, pkt)
            return

        record = self._flows[key]
        record.add_packet(pkt, direction)
        if record.complete:
            self.completed.append(record)
            del self._flows[key]

    def flush_timeouts(self, now: float | None = None) -> None:
        """Move flows idle for longer than timeout_s to self.completed."""
        now = now if now is not None else time.monotonic()
        # Use actual wall clock difference based on last packet ts
        # (We compare against wall time, not packet timestamp, for live capture)
        timed_out = [
            key for key, rec in self._flows.items()
            if (now - rec.last_seen()) >= self.timeout_s
        ]
        for key in timed_out:
            rec = self._flows.pop(key)
            rec.complete = True
            self.completed.append(rec)

    def drain_completed(self) -> list[FlowRecord]:
        """Return and clear the completed flow list."""
        out = self.completed
        self.completed = []
        return out


# ---------------------------------------------------------------------------
# Feature extraction — CIC-IDS2017 aligned
# ---------------------------------------------------------------------------
def _iat_stats(timestamps: list[float]) -> tuple[float, float, float, float, float]:
    """Return (total, mean, std, min, max) of inter-arrival times in microseconds."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    iats = [(timestamps[i] - timestamps[i - 1]) * 1_000_000 for i in range(1, len(timestamps))]
    total = sum(iats)
    mean = total / len(iats)
    if len(iats) > 1:
        variance = sum((x - mean) ** 2 for x in iats) / len(iats)
        std = math.sqrt(variance)
    else:
        std = 0.0
    return total, mean, std, min(iats), max(iats)


def _packet_length_stats(lengths: list[int]) -> tuple[float, float, float, float, float]:
    """Return (mean, std, min, max, variance)."""
    if not lengths:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    n = len(lengths)
    mn = min(lengths)
    mx = max(lengths)
    mean = sum(lengths) / n
    variance = sum((x - mean) ** 2 for x in lengths) / n if n > 1 else 0.0
    std = math.sqrt(variance)
    return mean, std, float(mn), float(mx), variance


def _active_idle_periods(
    timestamps: list[float], threshold_s: float = 1.0
) -> tuple[list[float], list[float]]:
    """Split flow into active/idle sub-periods based on a gap threshold.

    Returns (active_μs, idle_μs) — both in microseconds.
    """
    active: list[float] = []
    idle: list[float] = []
    if len(timestamps) < 2:
        return active, idle

    active_start = timestamps[0]
    prev = timestamps[0]
    for ts in timestamps[1:]:
        gap = ts - prev
        if gap >= threshold_s:
            period = (prev - active_start) * 1_000_000
            if period > 0:
                active.append(period)
            idle.append(gap * 1_000_000)
            active_start = ts
        prev = ts
    last_active = (prev - active_start) * 1_000_000
    if last_active > 0:
        active.append(last_active)
    return active, idle


def _period_stats(vals: list[float]) -> tuple[float, float, float, float]:
    """Return (mean, std, min, max) or zeros if empty."""
    if not vals:
        return 0.0, 0.0, 0.0, 0.0
    mean = sum(vals) / len(vals)
    variance = sum((x - mean) ** 2 for x in vals) / len(vals) if len(vals) > 1 else 0.0
    std = math.sqrt(variance)
    return mean, std, min(vals), max(vals)


def extract_canonical_features(
    pkts: list[_StoredPkt],
    key: tuple,
    init_win_fwd: int,
    init_win_bwd: int,
) -> dict[str, float]:
    """Compute all 77 CIC-IDS2017 canonical features from a completed flow.

    Units
    -----
    flow_duration         seconds  (CIC exports in seconds)
    IAT / active / idle   microseconds
    byte/count fields     raw integers cast to float
    rates                 per-second  (bytes/s, packets/s)
    """
    if not pkts:
        # Return zero-filled feature dict for empty flows (should not normally occur)
        from ml.schema import CANONICAL_FEATURES
        return {f: 0.0 for f in CANONICAL_FEATURES}

    _, _, src_port, dst_port, proto = key

    fwd = [p for p in pkts if p.direction == "fwd"]
    bwd = [p for p in pkts if p.direction == "bwd"]

    all_ts = [p.ts for p in pkts]
    fwd_ts = [p.ts for p in fwd]
    bwd_ts = [p.ts for p in bwd]

    t_start = all_ts[0]
    t_end = all_ts[-1]
    flow_duration = t_end - t_start  # seconds

    all_lengths = [p.length for p in pkts]
    fwd_lengths = [p.length for p in fwd]
    bwd_lengths = [p.length for p in bwd]

    fwd_payload = [p.payload_length for p in fwd]
    bwd_payload = [p.payload_length for p in bwd]

    total_fwd_packets = len(fwd)
    total_bwd_packets = len(bwd)
    total_length_fwd = sum(fwd_lengths)
    total_length_bwd = sum(bwd_lengths)

    # Packet-length stats (all packets)
    pkt_mean, pkt_std, pkt_min, pkt_max, pkt_var = _packet_length_stats(all_lengths)
    fwd_pkt_mean, fwd_pkt_std, fwd_pkt_min, fwd_pkt_max, _ = _packet_length_stats(fwd_lengths)
    bwd_pkt_mean, bwd_pkt_std, bwd_pkt_min, bwd_pkt_max, _ = _packet_length_stats(bwd_lengths)

    # Segment sizes (payload)
    avg_fwd_seg = (sum(fwd_payload) / len(fwd_payload)) if fwd_payload else 0.0
    avg_bwd_seg = (sum(bwd_payload) / len(bwd_payload)) if bwd_payload else 0.0

    avg_pkt_size = (sum(all_lengths) / len(all_lengths)) if all_lengths else 0.0

    # IATs
    flow_iat_total, flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max = _iat_stats(all_ts)
    fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_min, fwd_iat_max = _iat_stats(fwd_ts)
    bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_min, bwd_iat_max = _iat_stats(bwd_ts)

    # Rates
    duration_safe = max(flow_duration, 1e-6)
    flow_bytes_per_s = (total_length_fwd + total_length_bwd) / duration_safe
    flow_packets_per_s = (total_fwd_packets + total_bwd_packets) / duration_safe
    fwd_packets_per_s = total_fwd_packets / duration_safe
    bwd_packets_per_s = total_bwd_packets / duration_safe

    # Headers
    fwd_header_len = sum(p.header_length for p in fwd)
    bwd_header_len = sum(p.header_length for p in bwd)

    # TCP flags
    all_flags = [p.tcp_flags for p in pkts]
    fwd_flags = [p.tcp_flags for p in fwd]
    bwd_flags = [p.tcp_flags for p in bwd]

    def _flag_count(flag_list: list[int], mask: int) -> int:
        return sum(1 for f in flag_list if f & mask)

    fin_flag_count = _flag_count(all_flags, 0x01)
    syn_flag_count = _flag_count(all_flags, 0x02)
    rst_flag_count = _flag_count(all_flags, 0x04)
    psh_flag_count = _flag_count(all_flags, 0x08)
    ack_flag_count = _flag_count(all_flags, 0x10)
    urg_flag_count = _flag_count(all_flags, 0x20)
    ece_flag_count = _flag_count(all_flags, 0x40)
    cwr_flag_count = _flag_count(all_flags, 0x80)

    fwd_psh_flags = _flag_count(fwd_flags, 0x08)
    bwd_psh_flags = _flag_count(bwd_flags, 0x08)
    fwd_urg_flags = _flag_count(fwd_flags, 0x20)
    bwd_urg_flags = _flag_count(bwd_flags, 0x20)

    # Subflows (CIC: subflow = half of total; both directions split equally)
    subflow_fwd_packets = total_fwd_packets
    subflow_bwd_packets = total_bwd_packets
    subflow_fwd_bytes = total_length_fwd
    subflow_bwd_bytes = total_length_bwd

    # Active / idle periods
    active_vals, idle_vals = _active_idle_periods(all_ts)
    active_mean, active_std, active_min, active_max = _period_stats(active_vals)
    idle_mean, idle_std, idle_min, idle_max = _period_stats(idle_vals)

    # Min segment size forward (minimum non-zero payload in fwd direction)
    nonzero_fwd_payload = [p for p in fwd_payload if p > 0]
    min_seg_size_forward = float(min(nonzero_fwd_payload)) if nonzero_fwd_payload else 0.0

    # Init window bytes
    init_win_bytes_forward = float(max(init_win_fwd, 0))
    init_win_bytes_backward = float(max(init_win_bwd, 0))

    # act_data_pkt_fwd: fwd packets with at least 1 byte of payload
    act_data_pkt_fwd = sum(1 for p in fwd if p.payload_length > 0)

    # Down/up ratio
    down_up_ratio = (total_bwd_packets / total_fwd_packets) if total_fwd_packets > 0 else 0.0

    # Bulk rates — CICFlowMeter defines bulk as 4+ consecutive packets in 1s
    # Simplified approximation: zero (bulk analysis requires per-packet timestamps)
    bulk_zero = 0.0

    return {
        "ack_flag_count":           float(ack_flag_count),
        "act_data_pkt_fwd":         float(act_data_pkt_fwd),
        "active_max":               active_max,
        "active_mean":              active_mean,
        "active_min":               active_min,
        "active_std":               active_std,
        "avg_bwd_segment_size":     avg_bwd_seg,
        "avg_fwd_segment_size":     avg_fwd_seg,
        "avg_packet_size":          avg_pkt_size,
        "bwd_avg_bulk_rate":        bulk_zero,
        "bwd_avg_bytes_bulk":       bulk_zero,
        "bwd_avg_packets_bulk":     bulk_zero,
        "bwd_header_length":        float(bwd_header_len),
        "bwd_iat_max":              bwd_iat_max,
        "bwd_iat_mean":             bwd_iat_mean,
        "bwd_iat_min":              bwd_iat_min,
        "bwd_iat_std":              bwd_iat_std,
        "bwd_iat_total":            bwd_iat_total,
        "bwd_packet_length_max":    bwd_pkt_max,
        "bwd_packet_length_mean":   bwd_pkt_mean,
        "bwd_packet_length_min":    bwd_pkt_min,
        "bwd_packet_length_std":    bwd_pkt_std,
        "bwd_packets_per_s":        bwd_packets_per_s,
        "bwd_psh_flags":            float(bwd_psh_flags),
        "bwd_urg_flags":            float(bwd_urg_flags),
        "cwr_flag_count":           float(cwr_flag_count),
        "destination_port":         float(dst_port),
        "down_up_ratio":            down_up_ratio,
        "ece_flag_count":           float(ece_flag_count),
        "fin_flag_count":           float(fin_flag_count),
        "flow_bytes_per_s":         flow_bytes_per_s,
        "flow_duration":            flow_duration,
        "flow_iat_max":             flow_iat_max,
        "flow_iat_mean":            flow_iat_mean,
        "flow_iat_min":             flow_iat_min,
        "flow_iat_std":             flow_iat_std,
        "flow_packets_per_s":       flow_packets_per_s,
        "fwd_avg_bulk_rate":        bulk_zero,
        "fwd_avg_bytes_bulk":       bulk_zero,
        "fwd_avg_packets_bulk":     bulk_zero,
        "fwd_header_length":        float(fwd_header_len),
        "fwd_iat_max":              fwd_iat_max,
        "fwd_iat_mean":             fwd_iat_mean,
        "fwd_iat_min":              fwd_iat_min,
        "fwd_iat_std":              fwd_iat_std,
        "fwd_iat_total":            fwd_iat_total,
        "fwd_packet_length_max":    fwd_pkt_max,
        "fwd_packet_length_mean":   fwd_pkt_mean,
        "fwd_packet_length_min":    fwd_pkt_min,
        "fwd_packet_length_std":    fwd_pkt_std,
        "fwd_packets_per_s":        fwd_packets_per_s,
        "fwd_psh_flags":            float(fwd_psh_flags),
        "fwd_urg_flags":            float(fwd_urg_flags),
        "idle_max":                 idle_max,
        "idle_mean":                idle_mean,
        "idle_min":                 idle_min,
        "idle_std":                 idle_std,
        "init_win_bytes_backward":  init_win_bytes_backward,
        "init_win_bytes_forward":   init_win_bytes_forward,
        "min_seg_size_forward":     min_seg_size_forward,
        "packet_length_max":        pkt_max,
        "packet_length_mean":       pkt_mean,
        "packet_length_min":        pkt_min,
        "packet_length_std":        pkt_std,
        "packet_length_variance":   pkt_var,
        "psh_flag_count":           float(psh_flag_count),
        "rst_flag_count":           float(rst_flag_count),
        "subflow_bwd_bytes":        float(subflow_bwd_bytes),
        "subflow_bwd_packets":      float(subflow_bwd_packets),
        "subflow_fwd_bytes":        float(subflow_fwd_bytes),
        "subflow_fwd_packets":      float(subflow_fwd_packets),
        "syn_flag_count":           float(syn_flag_count),
        "total_bwd_packets":        float(total_bwd_packets),
        "total_fwd_packets":        float(total_fwd_packets),
        "total_length_bwd_packets": float(total_length_bwd),
        "total_length_fwd_packets": float(total_length_fwd),
        "urg_flag_count":           float(urg_flag_count),
    }
