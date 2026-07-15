import json
from pathlib import Path
from core.models import ExposureEvent

class BaselineEngine:
    """Tracks known exposures using a simple JSON state file to detect only new ones."""
    def __init__(self, baseline_file: str = "data/baseline.json"):
        self.baseline_file = Path(baseline_file)
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.state = self._load()

    def _load(self) -> set:
        """Loads known exposures as a set of 'ip:port' strings."""
        if not self.baseline_file.exists():
            return set()
        with self.baseline_file.open("r", encoding="utf-8") as f:
            return set(json.load(f))

    def _save(self) -> None:
        """Saves current exposures to disk."""
        with self.baseline_file.open("w", encoding="utf-8") as f:
            json.dump(list(self.state), f)

    def is_new_exposure(self, event: ExposureEvent) -> bool:
        """Returns True if this exposure hasn't been seen before. Saves it if new."""
        exposure_id = f"{event.ip}:{event.port}"
        if exposure_id in self.state:
            return False
        
        self.state.add(exposure_id)
        self._save()
        return True
