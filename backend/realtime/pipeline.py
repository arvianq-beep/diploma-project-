"""Real-time streaming inference pipeline.

StreamMonitor
-------------
Ingests RawPackets from any BaseCapture source, aggregates them into
complete network flows (via FlowAggregator), and runs two-stage AI inference
(Stage 1: RF detector, Stage 2: MLP verifier) in mini-batches.

Batch size is configurable (default 32).  Each batch triggers exactly:
  - 2 RF predict_proba calls  (main prob + stability ensemble)
  - 1 RF predict_proba call   (perturbation analysis)
  - 1 MLP forward pass        (verifier, per row)
for a total of 4 model calls regardless of how many flows are in the batch.

Usage
-----
    monitor = StreamMonitor(source="synthetic", batch_size=32)
    monitor.start(blocking=False)
    for result in monitor.results():
        print(result.final_status, result.detector_confidence)
    monitor.stop()

Flask SSE
---------
The StreamMonitor maintains an internal deque of StreamResult objects.
Flask can drain it via monitor.drain_results() and send them as SSE events.
"""

from __future__ import annotations

import json
import queue
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Deque, Iterator

from .capture import BaseCapture, make_capture_source
from .flow import FlowAggregator, FlowRecord, RawPacket


# ---------------------------------------------------------------------------
# StreamResult — final output for one completed flow
# ---------------------------------------------------------------------------
@dataclass
class StreamResult:
    """All information produced by the two-stage pipeline for a single flow."""

    # Timing
    processed_at: float          # Unix epoch seconds

    # Flow identification
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int

    # Stage 1 — RF detector
    detector_label: str          # "Network Attack" | "Benign"
    detector_confidence: float
    detector_stability: float
    detector_model_version: str

    # Stage 2 — MLP verifier
    final_status: str            # "Benign" | "Suspicious" | "Verified Threat"
    verification_confidence: float
    verifier_model_version: str
    recommended_action: str

    # 77-feature snapshot (canonical names → floats)
    feature_snapshot: dict[str, float]

    # Indicators from Stage 1
    triggered_indicators: list[str]

    def to_sse_dict(self) -> dict[str, Any]:
        """Compact representation for SSE / JSON serialisation."""
        return {
            "processed_at": self.processed_at,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "detector_label": self.detector_label,
            "detector_confidence": round(self.detector_confidence, 4),
            "detector_stability": round(self.detector_stability, 4),
            "final_status": self.final_status,
            "verification_confidence": round(self.verification_confidence, 4),
            "recommended_action": self.recommended_action,
            "triggered_indicators": self.triggered_indicators,
        }


# ---------------------------------------------------------------------------
# StreamMonitor
# ---------------------------------------------------------------------------
_STOP_SENTINEL = object()


class StreamMonitor:
    """Orchestrates packet capture → flow aggregation → batch AI inference.

    Parameters
    ----------
    source : str | BaseCapture
        Either a source name ("pyshark", "scapy", "csv", "synthetic") or an
        already-constructed BaseCapture instance.
    interface : str
        Network interface passed to pyshark/scapy.
    csv_path : str | None
        CSV path for CsvReplaySource.
    rate_limit : float
        Seconds between packets for csv/synthetic sources.
    attack_ratio : float
        Attack fraction for synthetic source.
    seed : int | None
        RNG seed for synthetic source.
    batch_size : int
        Number of completed flows to accumulate before running inference.
        Flows are also flushed when `flush_interval_s` elapses.
    flush_interval_s : float
        Maximum seconds to wait before flushing a partial batch.
    flow_timeout_s : float
        Idle timeout for FlowAggregator (seconds).
    console_output : bool
        Print each result to stdout.
    result_buffer_size : int
        Max StreamResult objects to keep in the in-memory deque.
    """

    def __init__(
        self,
        source: str | BaseCapture = "synthetic",
        *,
        interface: str = "eth0",
        csv_path: str | None = None,
        rate_limit: float = 0.05,
        attack_ratio: float = 0.3,
        seed: int | None = None,
        batch_size: int = 32,
        flush_interval_s: float = 2.0,
        flow_timeout_s: float = 30.0,
        console_output: bool = True,
        result_buffer_size: int = 1000,
    ) -> None:
        if isinstance(source, str):
            self._capture: BaseCapture = make_capture_source(
                source,
                interface=interface,
                csv_path=csv_path,
                rate_limit=rate_limit,
                attack_ratio=attack_ratio,
                seed=seed,
            )
        else:
            self._capture = source

        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.flow_timeout_s = flow_timeout_s
        self.console_output = console_output
        self._buffer: Deque[StreamResult] = deque(maxlen=result_buffer_size)

        self._running = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._inference_thread: threading.Thread | None = None
        self._flow_queue: queue.Queue[FlowRecord | object] = queue.Queue(maxsize=512)
        self._predictor = None
        self._verifier = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self, blocking: bool = True) -> None:
        """Start capture and inference threads.

        Parameters
        ----------
        blocking : bool
            If True, block until stop() is called.  If False, return
            immediately and let background threads do the work.
        """
        if self._running.is_set():
            return

        self._load_models()
        self._running.set()

        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="rt-capture"
        )
        self._inference_thread = threading.Thread(
            target=self._inference_loop, daemon=True, name="rt-inference"
        )
        self._capture_thread.start()
        self._inference_thread.start()

        if blocking:
            try:
                self._capture_thread.join()
                self._inference_thread.join()
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        """Signal threads to stop and wait for clean shutdown."""
        self._running.clear()
        try:
            self._flow_queue.put_nowait(_STOP_SENTINEL)
        except queue.Full:
            pass
        if self._capture_thread:
            self._capture_thread.join(timeout=5.0)
        if self._inference_thread:
            self._inference_thread.join(timeout=5.0)

    def results(self) -> Iterator[StreamResult]:
        """Blocking generator — yields StreamResult objects as they arrive."""
        seen = 0
        while self._running.is_set() or seen < len(self._buffer):
            if seen < len(self._buffer):
                # deque doesn't support random access by index efficiently,
                # so we snapshot it
                snapshot = list(self._buffer)
                for item in snapshot[seen:]:
                    yield item
                    seen += 1
            else:
                time.sleep(0.05)

    def drain_results(self) -> list[StreamResult]:
        """Return and clear all buffered results (for SSE endpoint use)."""
        out = list(self._buffer)
        self._buffer.clear()
        return out

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def status(self) -> dict[str, Any]:
        return {
            "running": self.is_running,
            "buffer_size": len(self._buffer),
            "detector_available": self._predictor.available if self._predictor else False,
            "verifier_available": self._verifier.available if self._verifier else False,
            "batch_size": self.batch_size,
            "flush_interval_s": self.flush_interval_s,
            "flow_timeout_s": self.flow_timeout_s,
        }

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------
    def _load_models(self) -> None:
        """Lazy-import and instantiate predictor + verifier."""
        if self._predictor is not None:
            return
        from ml.inference import MLPredictor
        from verification.inference import SecureDecisionVerificationService

        self._predictor = MLPredictor()
        self._verifier = SecureDecisionVerificationService(self._predictor)

    # ------------------------------------------------------------------
    # Capture thread
    # ------------------------------------------------------------------
    def _capture_loop(self) -> None:
        aggregator = FlowAggregator(timeout_s=self.flow_timeout_s)
        last_flush = time.monotonic()

        for pkt in self._capture:
            if not self._running.is_set():
                break

            aggregator.ingest(pkt)

            now = time.monotonic()
            if (now - last_flush) >= self.flow_timeout_s:
                aggregator.flush_timeouts(now)
                last_flush = now

            for flow in aggregator.drain_completed():
                try:
                    self._flow_queue.put(flow, timeout=1.0)
                except queue.Full:
                    pass  # drop if inference is too slow

        # drain remaining open flows on shutdown
        aggregator.flush_timeouts(time.monotonic())
        for flow in aggregator.drain_completed():
            try:
                self._flow_queue.put_nowait(flow)
            except queue.Full:
                pass
        self._flow_queue.put(_STOP_SENTINEL)

    # ------------------------------------------------------------------
    # Inference thread
    # ------------------------------------------------------------------
    def _inference_loop(self) -> None:
        batch: list[FlowRecord] = []
        last_flush = time.monotonic()

        while True:
            try:
                item = self._flow_queue.get(timeout=0.1)
            except queue.Empty:
                item = None

            if item is _STOP_SENTINEL:
                if batch:
                    self._process_batch(batch)
                break

            if item is not None:
                batch.append(item)  # type: ignore[arg-type]

            now = time.monotonic()
            should_flush = (
                len(batch) >= self.batch_size
                or (batch and (now - last_flush) >= self.flush_interval_s)
            )
            if should_flush:
                self._process_batch(batch)
                batch = []
                last_flush = now

        if not self._running.is_set() and batch:
            self._process_batch(batch)

    # ------------------------------------------------------------------
    # Batch inference
    # ------------------------------------------------------------------
    def _process_batch(self, flows: list[FlowRecord]) -> None:
        """Run two-stage inference on a batch of completed flows."""
        if not flows or self._predictor is None:
            return

        from ml.inference import FeatureValidationError
        from verification.features import run_perturbation_analysis_batch
        from verification.schema import BENIGN_STATUS, SUSPICIOUS_STATUS, VERIFIED_THREAT_STATUS

        # --- extract 77-feature snapshots ---
        snapshots: list[dict] = []
        records: list[FlowRecord] = []
        for flow in flows:
            try:
                snap = flow.extract_features()
                snapshots.append(snap)
                records.append(flow)
            except Exception:
                continue  # skip flows that fail feature extraction

        if not snapshots:
            return

        # --- Stage 1: batch RF detector (2 predict_proba calls) ---
        try:
            contexts = [{"source": "realtime"} for _ in snapshots]
            detector_outputs = self._predictor.predict_from_features_batch(snapshots, contexts)
        except (FeatureValidationError, Exception) as exc:
            print(f"[realtime] Batch detector error: {exc}", file=sys.stderr)
            return

        # --- Stage 2: batch verifier (1 RF call + 1 MLP per row) ---
        results: list[StreamResult] = []
        for i, (flow, snap, det_out) in enumerate(zip(records, snapshots, detector_outputs)):
            try:
                event = {"source": "realtime"}
                ver_decision = self._verifier.evaluate(event=event, detector_output=det_out)
                final_status = ver_decision.final_decision_status
            except Exception:
                # Verifier unavailable — use detector label as status
                final_status = (
                    SUSPICIOUS_STATUS if det_out.label != "Benign" else BENIGN_STATUS
                )
                ver_decision = None

            src_ip, dst_ip, src_port, dst_port, proto = flow.key

            result = StreamResult(
                processed_at=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                detector_label=det_out.label,
                detector_confidence=det_out.confidence,
                detector_stability=det_out.stability_score,
                detector_model_version=det_out.model_version,
                final_status=final_status,
                verification_confidence=(
                    ver_decision.verification_confidence if ver_decision else 0.0
                ),
                verifier_model_version=(
                    ver_decision.verifier_model_version
                    if ver_decision
                    else self._verifier.model_version
                ),
                recommended_action=(
                    ver_decision.recommended_action
                    if ver_decision
                    else ("Block" if det_out.label != "Benign" else "Allow")
                ),
                feature_snapshot=snap,
                triggered_indicators=det_out.triggered_indicators,
            )
            results.append(result)
            self._buffer.append(result)
            self._emit(result)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def _emit(self, result: StreamResult) -> None:
        """Print to console and trigger alert if threat confirmed."""
        if not self.console_output:
            return
        status_tag = {
            "Benign": "[ OK ]",
            "Suspicious": "[WARN]",
            "Verified Threat": "[ALERT]",
        }.get(result.final_status, "[????]")

        ts = time.strftime("%H:%M:%S", time.localtime(result.processed_at))
        print(
            f"{ts} {status_tag} "
            f"{result.src_ip}:{result.src_port} → "
            f"{result.dst_ip}:{result.dst_port}  "
            f"det={result.detector_label}({result.detector_confidence:.2f})  "
            f"status={result.final_status}  "
            f"stab={result.detector_stability:.2f}"
        )
        if result.final_status == "Verified Threat":
            print(
                f"  *** ALERT! Verified Threat from {result.src_ip}:{result.src_port} "
                f"to {result.dst_ip}:{result.dst_port} "
                f"(confidence={result.verification_confidence:.2f}) ***"
            )
