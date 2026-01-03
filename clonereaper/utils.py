import logging
import platform
import os
from typing import Optional, Tuple
from .config import Config

win32api_available = False
if platform.system() == "Windows":
    try:
        import win32file
        import win32con
        win32api_available = True
    except ImportError:
        pass


def setup_logging(level: int):
    """Configures logging."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def format_bytes(size: int) -> str:
    """Formats bytes into a human-readable string."""
    if size < 1024:
        return f"{size} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        size /= 1024
        if size < 1024:
            return f"{size:.2f} {unit}"
    return f"{size:.2f} PB"


def normalize_path(path: str, config: Config) -> str:
    """Adds Windows long path prefix if enabled."""
    if (
            config.long_paths_enabled
            and platform.system() == "Windows"
            and not path.startswith("\\\\?\\")
    ):
        # Use os.path.abspath to handle relative paths correctly
        return "\\\\?\\" + os.path.abspath(path)
    return path


def get_file_id_windows(file_path: str) -> Optional[Tuple[int, int]]:
    """Gets the unique file ID from NTFS MFT (Windows only)."""
    if not win32api_available:
        return None
    try:
        handle = win32file.CreateFile(
            file_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ
            | win32con.FILE_SHARE_WRITE
            | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        # The pywin32 function returns a tuple of 10 items.
        # The file index high/low are the 9th and 10th items (index 8 and 9).
        info = win32file.GetFileInformationByHandle(handle)
        handle.Close()
        return (info[8], info[9])
    except Exception as e:
        logging.warning(f"Could not get file ID for {file_path}: {e}")
        return None


def get_file_id_linux(file_path: str) -> Optional[Tuple[int, int]]:
    """Gets the unique file ID (device and inode) on Linux."""
    try:
        stat_info = os.stat(file_path)
        return (stat_info.st_dev, stat_info.st_ino)
    except OSError as e:
        logging.warning(f"Could not get file ID for {file_path}: {e}")
        return None


def get_file_id(file_path: str) -> Optional[Tuple[int, int]]:
    """Platform-agnostic file ID getter."""
    if platform.system() == "Windows":
        return get_file_id_windows(file_path)
    else:
        return get_file_id_linux(file_path)
