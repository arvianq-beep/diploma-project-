"""Capture sources for the real-time streaming pipeline.

Each source is an iterator that yields RawPacket objects.  Sources are tried
in order of preference; any source can be used independently.

Source classes
--------------
PysharkCapture      — live capture via pyshark (requires tshark installed)
ScapyCapture        — live capture via scapy  (requires libpcap / Npcap)
SyntheticFlowSource — generates random synthetic flows (testing / demo)

All imports of pyshark and scapy are deferred inside __init__ so that the
module can be imported on machines that have neither library installed.
"""

from __future__ import annotations

import random
import threading
import time
from abc import ABC, abstractmethod
from typing import Iterator

from .flow import RawPacket


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------
class BaseCapture(ABC):
    """Abstract capture source — yields RawPacket objects."""

    @abstractmethod
    def packets(self) -> Iterator[RawPacket]:
        """Yield RawPacket objects indefinitely (or until exhausted)."""

    def __iter__(self) -> Iterator[RawPacket]:
        return self.packets()

    def stop(self) -> None:
        """Signal capture to stop. No-op by default; override as needed."""


# ---------------------------------------------------------------------------
# PysharkCapture
# ---------------------------------------------------------------------------
class PysharkCapture(BaseCapture):
    """Live packet capture backed by pyshark (tshark).

    Parameters
    ----------
    interface : str
        Network interface name (e.g. "eth0", "Wi-Fi").
    bpf_filter : str
        Berkeley Packet Filter expression (default: "ip").
    timeout : float | None
        Seconds before capture auto-stops (None = infinite).
    """

    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: str = "ip",
        timeout: float | None = None,
        promiscuous: bool = False,
    ) -> None:
        try:
            import pyshark as _pyshark  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "pyshark is required for PysharkCapture. "
                "Install it with: pip install pyshark"
            ) from exc
        self._pyshark = _pyshark
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.timeout = timeout
        self.promiscuous = promiscuous
        self._stop_event = threading.Event()
        # Set by _sniff_thread so stop() can actively kill tshark.
        self._live_capture = None
        self._capture_loop = None

    def stop(self) -> None:
        self._stop_event.set()
        # Actively schedule close_async() on the capture's own event loop.
        # This kills the tshark subprocess immediately instead of waiting
        # for the next packet to arrive.
        import asyncio
        capture = self._live_capture
        loop = self._capture_loop
        if capture is not None and loop is not None and not loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(capture.close_async(), loop)
            except Exception:
                pass

    def packets(self) -> Iterator[RawPacket]:
        import asyncio
        import queue as queue_module

        q: queue_module.Queue[RawPacket | None] = queue_module.Queue()
        self._stop_event.clear()
        self._live_capture = None
        self._capture_loop = None

        def _sniff_thread() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            kwargs: dict = {
                "interface": self.interface,
                "bpf_filter": self.bpf_filter,
            }
            # Disable promiscuous mode via tshark -p flag (avoids DNS breakage
            # on Windows). Try the pyshark kwarg first; fall back to tshark arg.
            import inspect
            if "use_promiscuous_mode" in inspect.signature(
                self._pyshark.LiveCapture.__init__
            ).parameters:
                kwargs["use_promiscuous_mode"] = self.promiscuous
            elif not self.promiscuous:
                kwargs["custom_parameters"] = ["-p"]
            capture = self._pyshark.LiveCapture(**kwargs)
            # Expose to stop() before blocking on sniff_continuously().
            self._live_capture = capture
            self._capture_loop = loop
            try:
                for pkt in capture.sniff_continuously():
                    if self._stop_event.is_set():
                        break
                    parsed = self._parse(pkt)
                    if parsed is not None:
                        q.put(parsed)
            except Exception:
                # Expected when close_async() kills tshark mid-read.
                pass
            finally:
                self._live_capture = None
                self._capture_loop = None
                # Close in the owning thread/loop to avoid __del__ errors.
                try:
                    if not loop.is_closed():
                        loop.run_until_complete(capture.close_async())
                except Exception:
                    pass
                try:
                    if not loop.is_closed():
                        loop.close()
                except Exception:
                    pass
                q.put(None)  # sentinel — signals packets() to return

        thread = threading.Thread(target=_sniff_thread, daemon=True)
        thread.start()

        while True:
            try:
                item = q.get(timeout=0.5)
            except queue_module.Empty:
                if self._stop_event.is_set():
                    break
                continue
            if item is None:
                break
            yield item

    @staticmethod
    def _parse(pkt) -> RawPacket | None:
        """Convert a pyshark packet to RawPacket, or return None if not parseable."""
        try:
            if not hasattr(pkt, "ip"):
                return None
            ts = float(pkt.sniff_timestamp)
            src_ip = str(pkt.ip.src)
            dst_ip = str(pkt.ip.dst)
            proto_num = int(pkt.ip.proto)
            ip_hdr_len = int(pkt.ip.hdr_len) if hasattr(pkt.ip, "hdr_len") else 20
            total_len = int(pkt.ip.len) if hasattr(pkt.ip, "len") else len(pkt)
            payload_len = total_len - ip_hdr_len

            src_port, dst_port, tcp_flags, tcp_window = 0, 0, 0, 0

            if hasattr(pkt, "tcp"):
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                tcp_flags = int(pkt.tcp.flags, 16) if hasattr(pkt.tcp, "flags") else 0
                tcp_window = int(pkt.tcp.window_size_value) if hasattr(pkt.tcp, "window_size_value") else 0
            elif hasattr(pkt, "udp"):
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)

            return RawPacket(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto_num,
                length=total_len,
                payload_length=max(payload_len, 0),
                ip_header_length=ip_hdr_len,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
            )
        except Exception:
            return None


# ---------------------------------------------------------------------------
# ScapyCapture
# ---------------------------------------------------------------------------
class ScapyCapture(BaseCapture):
    """Live packet capture backed by scapy.

    Parameters
    ----------
    interface : str | None
        Network interface (None = default interface selected by scapy).
    bpf_filter : str
        BPF filter string (default: "ip").
    count : int
        0 = capture indefinitely.
    """

    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str = "ip",
        count: int = 0,
    ) -> None:
        try:
            from scapy.all import sniff as _sniff  # type: ignore[import]
            from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "scapy is required for ScapyCapture. "
                "Install it with: pip install scapy"
            ) from exc
        self._sniff = _sniff
        self._IP = IP
        self._TCP = TCP
        self._UDP = UDP
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def packets(self) -> Iterator[RawPacket]:
        import queue as queue_module

        q: queue_module.Queue[RawPacket | None] = queue_module.Queue()
        self._stop_event.clear()

        def _on_pkt(pkt) -> None:
            parsed = self._parse(pkt)
            if parsed is not None:
                q.put(parsed)

        def _sniff_thread() -> None:
            kwargs: dict = {
                "prn": _on_pkt,
                "store": False,
                "filter": self.bpf_filter,
                # stop_filter is checked after each packet; stops the sniff loop.
                "stop_filter": lambda _: self._stop_event.is_set(),
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if self.count > 0:
                kwargs["count"] = self.count
            self._sniff(**kwargs)
            q.put(None)  # sentinel

        thread = threading.Thread(target=_sniff_thread, daemon=True)
        thread.start()

        while True:
            try:
                item = q.get(timeout=0.5)
            except queue_module.Empty:
                if self._stop_event.is_set():
                    break
                continue
            if item is None:
                break
            yield item

    def _parse(self, pkt) -> RawPacket | None:
        try:
            if self._IP not in pkt:
                return None
            ip = pkt[self._IP]
            ts = float(pkt.time)
            proto_num = int(ip.proto)
            ip_hdr_len = ip.ihl * 4 if hasattr(ip, "ihl") else 20
            total_len = int(ip.len) if hasattr(ip, "len") else len(pkt)
            payload_len = max(total_len - ip_hdr_len, 0)

            src_port, dst_port, tcp_flags, tcp_window = 0, 0, 0, 0

            if self._TCP in pkt:
                tcp = pkt[self._TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                tcp_flags = int(tcp.flags)
                tcp_window = int(tcp.window)
            elif self._UDP in pkt:
                from scapy.layers.inet import UDP  # type: ignore[import]
                udp = pkt[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

            return RawPacket(
                timestamp=ts,
                src_ip=str(ip.src),
                dst_ip=str(ip.dst),
                src_port=src_port,
                dst_port=dst_port,
                proto=proto_num,
                length=total_len,
                payload_length=payload_len,
                ip_header_length=ip_hdr_len,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
            )
        except Exception:
            return None


# ---------------------------------------------------------------------------
# SyntheticFlowSource
# ---------------------------------------------------------------------------
_ATTACK_PORTS = [22, 23, 80, 443, 3389, 8080, 21, 25]
_BENIGN_PORTS = [80, 443, 53, 8080, 8443, 993, 995]


class SyntheticFlowSource(BaseCapture):
    """Generates synthetic RawPacket objects for testing.

    Alternates between benign-like and attack-like traffic patterns so that
    the model exercises both classification branches.

    Parameters
    ----------
    rate_limit : float
        Seconds between emitted packets (default 0.05).
    attack_ratio : float
        Fraction of flows that simulate attack traffic (0–1).
    seed : int | None
        Random seed for reproducibility.
    """

    def __init__(
        self,
        rate_limit: float = 0.05,
        attack_ratio: float = 0.3,
        seed: int | None = None,
    ) -> None:
        self.rate_limit = rate_limit
        self.attack_ratio = attack_ratio
        self._rng = random.Random(seed)
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def packets(self) -> Iterator[RawPacket]:
        self._stop_event.clear()
        while not self._stop_event.is_set():
            is_attack = self._rng.random() < self.attack_ratio
            for pkt in self._make_flow(is_attack):
                yield pkt
                if self.rate_limit > 0:
                    # Interruptible sleep: wakes immediately on stop().
                    self._stop_event.wait(timeout=self.rate_limit)
                if self._stop_event.is_set():
                    return

    def _make_flow(self, is_attack: bool) -> list[RawPacket]:
        """Generate a short synthetic flow (3–20 packets) as a list of RawPackets."""
        rng = self._rng
        now = time.time()

        if is_attack:
            n_fwd = rng.randint(10, 50)
            n_bwd = rng.randint(1, 5)
            dst_port = rng.choice(_ATTACK_PORTS)
            pkt_size = rng.randint(40, 120)
            iat_s = 0.0001   # very fast — attack
        else:
            n_fwd = rng.randint(3, 15)
            n_bwd = rng.randint(2, 12)
            dst_port = rng.choice(_BENIGN_PORTS)
            pkt_size = rng.randint(200, 1400)
            iat_s = rng.uniform(0.01, 0.2)

        src_ip = f"192.168.{rng.randint(1,254)}.{rng.randint(1,254)}"
        dst_ip = f"10.0.{rng.randint(0,255)}.{rng.randint(1,254)}"
        src_port = rng.randint(1024, 65535)
        proto = 6  # TCP

        pkts: list[RawPacket] = []
        ts = now
        for i in range(n_fwd + n_bwd):
            direction_fwd = i < n_fwd
            flags = 0x02 if i == 0 else (0x10 | (0x01 if i == n_fwd + n_bwd - 1 else 0))
            p_src_ip = src_ip if direction_fwd else dst_ip
            p_dst_ip = dst_ip if direction_fwd else src_ip
            p_src_port = src_port if direction_fwd else dst_port
            p_dst_port = dst_port if direction_fwd else src_port
            pkts.append(RawPacket(
                timestamp=ts,
                src_ip=p_src_ip,
                dst_ip=p_dst_ip,
                src_port=p_src_port,
                dst_port=p_dst_port,
                proto=proto,
                length=pkt_size,
                payload_length=max(pkt_size - 20, 0),
                ip_header_length=20,
                tcp_flags=flags,
                tcp_window=65535,
            ))
            ts += iat_s + rng.uniform(0, iat_s * 0.1)

        return pkts


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------
def make_capture_source(
    source: str,
    *,
    interface: str = "eth0",
    rate_limit: float = 0.0,
    attack_ratio: float = 0.3,
    seed: int | None = None,
    promiscuous: bool = False,
) -> BaseCapture:
    """Factory: return the appropriate capture source by name.

    Parameters
    ----------
    source : str
        One of "pyshark", "scapy", "synthetic".
    interface : str
        Network interface (pyshark / scapy only).
    rate_limit : float
        Seconds between packets (synthetic only).
    attack_ratio : float
        Fraction of attacks in synthetic mode.
    seed : int | None
        Random seed for synthetic mode.
    """
    if source == "pyshark":
        return PysharkCapture(interface=interface, promiscuous=promiscuous)
    if source == "scapy":
        return ScapyCapture(interface=interface)
    if source == "synthetic":
        return SyntheticFlowSource(rate_limit=rate_limit, attack_ratio=attack_ratio, seed=seed)
    raise ValueError(
        f"Unknown capture source {source!r}. "
        "Choose from: 'pyshark', 'scapy', 'synthetic'."
    )
