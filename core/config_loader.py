from pathlib import Path
import yaml


class ConfigLoader:
    """Loads and validates the project configuration."""

    def __init__(self, config_path: str = "config/assets.yaml"):
        self.config_path = Path(config_path)

    def load(self) -> dict:
        """Read the YAML configuration file."""

        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )

        with self.config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        if not data:
            raise ValueError("Configuration file is empty.")

        if "assets" not in data:
            raise ValueError("'assets' section is missing.")

        if not isinstance(data["assets"], list):
            raise TypeError("'assets' must be a list.")

        return data