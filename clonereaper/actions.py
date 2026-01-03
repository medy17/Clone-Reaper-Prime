import logging
import os
import shutil
import time
import platform
from typing import Dict, List, Tuple, Optional, Callable, Any

try:
    import win32file
    win32_available = True
except ImportError:
    win32_available = False

from .config import Config, QUARANTINE_FOLDER_NAME
from .utils import normalize_path, format_bytes

def calculate_wasted_space(
        duplicates: Dict[str, List[str]], config: Config
) -> int:
    """Calculates the total wasted space from duplicate files."""
    wasted_space = 0
    for file_list in duplicates.values():
        if not file_list:
            continue
        try:
            norm_path = normalize_path(file_list[0], config)
            file_size = os.lstat(norm_path).st_size
            if file_size >= config.min_size:
                wasted_space += file_size * (len(file_list) - 1)
        except OSError as e:
            logging.warning(
                f"Could not get size for {file_list[0]} "
                f"during waste calculation: {e}"
            )
    return wasted_space


def select_file_to_keep(
        file_list: List[str], strategy: str, config: Config
) -> Tuple[str, List[str]]:
    """Selects which file to keep based on the chosen strategy."""
    if not file_list:
        return "", []

    if strategy == "first":
        return file_list[0], file_list[1:]

    sort_key: Optional[Callable[[str], Any]] = None
    reverse_sort = False

    if strategy == "shortest":
        sort_key = len
    elif strategy == "longest":
        sort_key = len
        reverse_sort = True
    elif strategy == "oldest":
        sort_key = lambda p: os.path.getmtime(normalize_path(p, config))
    elif strategy == "newest":
        sort_key = lambda p: os.path.getmtime(normalize_path(p, config))
        reverse_sort = True
    # NOTE: GPS strategy would require a library like 'Pillow' or 'exifread'
    # and would be added here.

    if sort_key:
        try:
            sorted_list = sorted(
                file_list, key=sort_key, reverse=reverse_sort
            )
            return sorted_list[0], sorted_list[1:]
        except OSError as e:
            logging.warning(
                f"Could not apply sort strategy due to error: {e}. Keeping first."
            )
            return file_list[0], file_list[1:]
    else:
        return file_list[0], file_list[1:]


def perform_actions(
        duplicates: Dict[str, List[str]], config: Config
) -> Tuple[int, int]:
    """Performs the selected action (delete, quarantine, link) on duplicates."""
    if not duplicates or config.action_mode == "none":
        return 0, 0

    total_processed_count = 0
    total_saved_size = 0
    action_verb = "Processing"
    if config.dry_run:
        action_verb = f"[DRY RUN] Would {config.action_mode}"
    elif config.action_mode == "delete":
        action_verb = "Deleting"
    elif config.action_mode == "quarantine":
        action_verb = "Quarantining"
        # Create quarantine directory if it doesn't exist
        if not os.path.exists(config.quarantine_path):
            os.makedirs(config.quarantine_path)
            print(f"Created quarantine directory: {config.quarantine_path}")
    elif config.action_mode == "link":
        action_verb = "Linking"

    print(
        f"\n{action_verb} duplicates (keeping: {config.keep_strategy})..."
    )

    for file_hash, file_list in duplicates.items():
        if len(file_list) < 2:
            continue

        keep_file, process_list = select_file_to_keep(
            file_list, config.keep_strategy, config
        )
        norm_keep_path = normalize_path(keep_file, config)

        for file_to_process in process_list:
            norm_process_path = normalize_path(file_to_process, config)
            try:
                file_size = os.lstat(norm_process_path).st_size
                print(
                    f"  {action_verb}: {file_to_process} ({format_bytes(file_size)})",
                    end="\r",
                )

                if not config.dry_run:
                    if config.action_mode == "delete":
                        os.remove(norm_process_path)
                    elif config.action_mode == "quarantine":
                        # Move to quarantine, handle potential name conflicts
                        dest_name = os.path.basename(file_to_process)
                        dest_path = os.path.join(
                            config.quarantine_path, dest_name
                        )
                        if os.path.exists(dest_path):
                            # Simple conflict resolution: append timestamp
                            base, ext = os.path.splitext(dest_name)
                            timestamp = int(time.time() * 1000)
                            dest_name = f"{base}_{timestamp}{ext}"
                            dest_path = os.path.join(
                                config.quarantine_path, dest_name
                            )
                        shutil.move(norm_process_path, dest_path)
                    elif config.action_mode == "link":
                        os.remove(norm_process_path)
                        if platform.system() == "Windows":
                            if win32_available:
                                win32file.CreateHardLink(
                                    norm_process_path, norm_keep_path
                                )
                            else:
                                logging.error("Cannot create hardlink: pywin32 not installed.")
                        else:  # Linux/macOS
                            os.link(norm_keep_path, norm_process_path)

                total_processed_count += 1
                total_saved_size += file_size

            except Exception as e:
                print()  # Ensure error message is on new line
                logging.error(
                    f"Error processing {file_to_process}: {e}"
                )

    print(
        f"Action process complete. {total_processed_count} files processed.          "
    )
    return total_processed_count, total_saved_size
