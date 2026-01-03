import json
import os
import platform
from typing import Dict, Any, Optional, List

# Constants
DEFAULT_HASH_ALGO = "sha256"
DEFAULT_CHUNK_SIZE = 65536  # 64KB for hashing
DEFAULT_MIN_FILE_SIZE = 1  # Minimum size in bytes to consider
DEFAULT_WORKERS = max(1, os.cpu_count() // 2) if os.cpu_count() else 1
QUARANTINE_FOLDER_NAME = "CloneReaper_Quarantine"

win32api_available = False
if platform.system() == "Windows":
    try:
        import win32file
        import win32con
        win32api_available = True
    except ImportError:
        pass


class Config:
    """Holds all configuration settings for a scan and action session."""

    def __init__(self):
        # Core Scan Settings
        self.directory: str = ""
        self.min_size: int = DEFAULT_MIN_FILE_SIZE
        self.hash_algo: str = DEFAULT_HASH_ALGO
        self.partial_hash: bool = False
        self.workers: int = DEFAULT_WORKERS

        # Feature Toggles
        self.check_hardlinks: bool = win32api_available
        self.long_paths_enabled: bool = False
        self.dry_run: bool = True
        self.verbose_logging: bool = False
        self.file_patterns: List[str] = [] # New feature: include/exclude patterns (glob)
        # For simplicity, if this list is not empty, only files matching one of these patterns are scanned.
        # Negative patterns (start with !) could exclude.

        # Action Settings
        self.action_mode: str = "none"
        self.keep_strategy: str = "first"
        self.quarantine_path: Optional[str] = None
        self.confirmations: int = 2

        # Reporting Settings
        self.enable_reports: bool = False
        self.report_format: str = "txt"
        self.report_path: str = "."

        # Automation & Integration Settings
        self.import_report_path: Optional[str] = None
        self.email_config: Dict[str, Any] = {"enabled": False}
        self.media_server_config: Dict[str, Any] = {"enabled": False}

    def save(self, path: str):
        """Saves the current configuration to a JSON file."""
        print(f"Saving configuration to {path}...")
        try:
            # We save the __dict__ which contains all the instance attributes
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.__dict__, f, indent=2)
        except IOError as e:
            print(f"Error: Could not save configuration file: {e}")

    @staticmethod
    def load(path: str) -> 'Config':
        """Loads configuration from a JSON file, or returns a default config."""
        config = Config()  # Start with a default config
        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded_data = json.load(f)
                # Update the default config with the loaded data
                config.__dict__.update(loaded_data)
            print(f"Configuration loaded from {path}.")
        except FileNotFoundError:
            print("No configuration file found. Using default settings.")
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Error reading config file: {e}. Using default settings.")
        return config
