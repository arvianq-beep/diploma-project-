from __future__ import annotations

"""CUSUM-based sudden concept drift detector for the IDS pipeline.

Monitors a sequential stream of scalar observations (one per inference batch or
per single-event analysis call) and raises an alarm when the lower one-sided
CUSUM statistic crosses the control limit — typically within 3-10 observations
of a sudden concept drift onset.

Algorithm (lower one-sided CUSUM):
    Warmup phase (first `warmup` observations):
        Collect baseline mean µ₀ and std σ₀ from the stream itself.
    Detection phase:
        S_t = max(0,  S_{t-1} + (µ₀ − k·σ₀) − x_t)
        Alarm when S_t > h·σ₀.
    After alarm: S resets to 0, cooldown suppresses further alarms for
    `cooldown` observations.

Tuning defaults (suitable for detector_stability ∈ [0, 1]):
    warmup   = 20   observations before alarms are enabled
    k        = 0.50 allowable slack (σ units); detects shifts > 0.5 σ
    h        = 4.00 control limit (σ units); ≈0.003 false-alarm rate per obs
    cooldown = 20   observations where new alarms are suppressed after a fire

Thread-safety: all public methods are protected by an internal Lock.
"""

import threading
from typing import Any


class CUSUMDriftDetector:
    """Lower one-sided CUSUM detector for sudden downward shifts.

    Intended signal: mean detector_stability per batch (Monitor mode) or
    per single analysis call (Analysis mode).  A sudden drop signals that the
    RF ensemble is becoming inconsistent — the classic symptom of concept drift.
    """

    def __init__(
        self,
        warmup: int = 20,
        k: float = 0.50,
        h: float = 4.0,
        cooldown: int = 20,
    ) -> None:
        self._warmup = warmup
        self._k = k
        self._h = h
        self._cooldown = cooldown

        self._lock = threading.Lock()
        self._warmup_buf: list[float] = []
        self._n: int = 0
        self._mu0: float | None = None
        self._sigma0: float | None = None
        self._s: float = 0.0
        self._drift_active: bool = False
        self._cooldown_remaining: int = 0
        self._total_alarms: int = 0
        self._last_alarm_at: int | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, value: float) -> dict[str, Any]:
        """Feed one scalar observation.  Returns current detector state."""
        with self._lock:
            self._n += 1
            return self._step(float(value))

    def state(self) -> dict[str, Any]:
        """Return current detector state without feeding an observation."""
        with self._lock:
            return self._snapshot(alarmed=False)

    def reset(self) -> None:
        """Reset CUSUM accumulator and drift flag; keeps learned baseline."""
        with self._lock:
            self._s = 0.0
            self._drift_active = False
            self._cooldown_remaining = 0

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _step(self, x: float) -> dict[str, Any]:
        # Phase 1: warmup — accumulate baseline stats, no alarms
        if self._mu0 is None:
            self._warmup_buf.append(x)
            if len(self._warmup_buf) >= self._warmup:
                mu = sum(self._warmup_buf) / len(self._warmup_buf)
                variance = sum((v - mu) ** 2 for v in self._warmup_buf) / len(self._warmup_buf)
                sigma = max(variance ** 0.5, 1e-4)
                self._mu0 = mu
                self._sigma0 = sigma
            return self._snapshot(alarmed=False)

        # Phase 2: detection
        k_abs = self._k * self._sigma0  # slack in original units
        h_abs = self._h * self._sigma0  # control limit in original units

        self._s = max(0.0, self._s + (self._mu0 - k_abs - x))

        # Cooldown countdown
        alarmed = False
        if self._cooldown_remaining > 0:
            self._cooldown_remaining -= 1
            if self._cooldown_remaining == 0:
                self._drift_active = False
        elif self._s > h_abs:
            alarmed = True
            self._drift_active = True
            self._total_alarms += 1
            self._last_alarm_at = self._n
            self._cooldown_remaining = self._cooldown
            self._s = 0.0

        return self._snapshot(alarmed=alarmed)

    def _snapshot(self, alarmed: bool) -> dict[str, Any]:
        in_warmup = self._mu0 is None
        return {
            "observations": self._n,
            "in_warmup": in_warmup,
            "warmup_remaining": max(0, self._warmup - len(self._warmup_buf)) if in_warmup else 0,
            "drift_active": self._drift_active,
            "alarmed_now": alarmed,
            "total_alarms": self._total_alarms,
            "last_alarm_at_observation": self._last_alarm_at,
            "cusum_s": round(self._s, 4),
            "baseline_mean": round(self._mu0, 4) if self._mu0 is not None else None,
            "baseline_std": round(self._sigma0, 6) if self._sigma0 is not None else None,
            "control_limit": round(self._h * self._sigma0, 4) if self._sigma0 is not None else None,
            "cooldown_remaining": self._cooldown_remaining,
        }
