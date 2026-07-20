import os
import json
from pathlib import Path
from core.models import ExposureEvent

class BaselineEngine:
    """Tracks stateful status (open/closed) of scanned exposures to detect changes over time."""
    
    def __init__(self, baseline_file: str = None):
        if baseline_file is None:
            # Check if local data directory is writable; fallback to /tmp for Vercel Serverless
            target_path = Path("data/baseline.json")
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                test_file = target_path.parent / ".write_test"
                test_file.touch()
                test_file.unlink()
                self.baseline_file = target_path
            except (OSError, PermissionError):
                self.baseline_file = Path("/tmp/baseline.json")
                self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.baseline_file = Path(baseline_file)
            try:
                self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError):
                self.baseline_file = Path("/tmp/baseline.json")
                self.baseline_file.parent.mkdir(parents=True, exist_ok=True)

        self.state = self._load() # Map of "ip:port" -> "open"/"closed"

    def _load(self) -> dict:
        """Loads baseline state as a dictionary of ip:port mapping to status."""
        if not self.baseline_file.exists():
            return {}
        try:
            with self.baseline_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self) -> None:
        """Saves current state to disk."""
        try:
            with self.baseline_file.open("w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=4)
        except Exception:
            pass

    def get_status(self, ip: str, port: int) -> str:
        """Returns the last known status ('open' or 'closed') or None if never seen."""
        return self.state.get(f"{ip}:{port}")

    def update_status(self, ip: str, port: int, status: str) -> None:
        """Updates the status of an exposure and saves to baseline file."""
        self.state[f"{ip}:{port}"] = status
        self._save()

    def get_currently_open(self) -> set:
        """Returns a set of 'ip:port' strings currently recorded as open."""
        return {key for key, value in self.state.items() if value == "open"}
