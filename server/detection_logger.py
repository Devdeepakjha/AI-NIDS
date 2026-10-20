"""
server/detection_logger.py
=============================================================================
Phase 6: Real-time detection event logging.
Thread-safe CSV logger for recording ML intrusion detection events.

Target file: data/detection_events.csv
Schema:
  timestamp,client_ip,prediction,intrusion_probability,status
=============================================================================
"""

import csv
import os
import threading
from datetime import datetime

DETECTION_LOG_COLUMNS = [
    "timestamp",
    "client_ip",
    "prediction",
    "intrusion_probability",
    "status"
]


class DetectionLogger:
    """
    Thread-safe logger for intrusion detection events.
    """

    def __init__(self, log_path: str = None):
        if log_path is None:
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            log_path = os.path.join(project_root, "data", "detection_events.csv")
        self.log_path = os.path.abspath(log_path)
        self._lock = threading.Lock()
        self.events_logged = 0
        self._ensure_header()

    def _ensure_header(self) -> None:
        """Create file and write header if file does not exist or is empty."""
        with self._lock:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            needs_header = not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0
            if needs_header:
                try:
                    with open(self.log_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(DETECTION_LOG_COLUMNS)
                except OSError as e:
                    print(f"[DetectionLogger] Error writing header: {e}")

    def log_event(self, client_ip: str, prediction: str, intrusion_probability: float, status: str = "SUCCESS") -> bool:
        """
        Record a single detection event thread-safely.
        Returns True on success, False on I/O failure.
        """
        now_str = datetime.now().isoformat()
        row = [
            now_str,
            str(client_ip),
            str(prediction),
            f"{float(intrusion_probability):.6f}" if intrusion_probability is not None else "0.000000",
            str(status)
        ]
        with self._lock:
            try:
                with open(self.log_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(row)
                self.events_logged += 1
                return True
            except OSError as e:
                print(f"[DetectionLogger] Warning: failed to write detection event: {e}")
                return False

    def clear(self) -> None:
        """Reset the detection log (used in testing)."""
        with self._lock:
            if os.path.exists(self.log_path):
                try:
                    os.remove(self.log_path)
                except OSError:
                    pass
            self.events_logged = 0
        self._ensure_header()
