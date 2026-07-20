import os
from pathlib import Path
import yaml

class ConfigLoader:
    """Loads and validates the project configuration with full environment and YAML correlation."""

    def __init__(self, config_path: str = "config/assets.yaml"):
        target_path = Path(config_path)
        if not target_path.exists():
            tmp_path = Path("/tmp/config/assets.yaml")
            if tmp_path.exists():
                self.config_path = tmp_path
            else:
                self.config_path = target_path
        else:
            self.config_path = target_path

    def load(self) -> dict:
        """Read YAML configuration file and merge correlated environment variables."""
        data = {"organization": "MITS", "assets": []}
        if self.config_path.exists():
            try:
                with self.config_path.open("r", encoding="utf-8") as file:
                    loaded = yaml.safe_load(file)
                    if isinstance(loaded, dict):
                        data.update(loaded)
            except Exception:
                pass

        if "assets" not in data or not isinstance(data.get("assets"), list):
            data["assets"] = []

        # Merge environment variables for complete project-wide field correlation
        data["organization"] = data.get("organization") or os.getenv("ORGANIZATION", "MITS")
        data["splunk_url"] = os.getenv("SPLUNK_URL", "https://13.205.90.142:8088/services/collector/event")
        data["splunk_token"] = os.getenv("SPLUNK_HEC_TOKEN", "")
        data["censys_token"] = os.getenv("CENSYS_API_TOKEN", "")
        data["scan_timeout"] = float(os.getenv("SCAN_TIMEOUT", "2.5"))

        return data