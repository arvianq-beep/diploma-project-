"""Real-time network traffic monitoring pipeline.

Modes
-----
offline  — static dataset analysis (default, existing behaviour unchanged)
realtime — live packet capture via pyshark/scapy or synthetic/CSV fallback

Entry points
------------
from realtime.pipeline import StreamMonitor
monitor = StreamMonitor(source="pyshark", interface="eth0")
monitor.start(blocking=False)
for result in monitor.results():
    print(result)
"""

from .pipeline import StreamMonitor, StreamResult

__all__ = ["StreamMonitor", "StreamResult"]
