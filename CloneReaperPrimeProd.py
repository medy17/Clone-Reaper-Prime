#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CloneReaper Prime: Advanced Duplicate File Finder and Manager
"""

import os
import sys
import smtplib
import hashlib
import collections
import platform
import time
import logging
import json
import csv
import shutil
import argparse
from multiprocessing import Pool, cpu_count
from typing import List, Dict, Tuple, Optional, Callable, Any, NamedTuple
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

win32api_available = False
if platform.system() == "Windows":
    try:
        import win32file
        import win32con

        win32api_available = True
    except ImportError:
        print(
            "Note: 'pywin32' not found. "
            "Windows-specific features like hardlink detection/creation "
            "will be disabled."
        )
        pass

DEFAULT_HASH_ALGO = "sha256"
DEFAULT_CHUNK_SIZE = 65536  # 64KB for hashing
DEFAULT_MIN_FILE_SIZE = 1  # Minimum size in bytes to consider
DEFAULT_WORKERS = max(1, cpu_count() // 2)
QUARANTINE_FOLDER_NAME = "CloneReaper_Quarantine"


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
        # --- THIS IS THE FIX ---
        # Before: return (info.nFileIndexHigh, info.nFileIndexLow)
        # After:
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


# --- Core Logic (Largely unchanged, but adapted to use Config object) ---
def compute_hash_worker(
        args_tuple: Tuple[str, Config]
) -> Tuple[str, Optional[str]]:
    """Worker function for parallel hashing."""
    file_path, config = args_tuple
    norm_path = normalize_path(file_path, config)
    try:
        hasher = hashlib.new(config.hash_algo)
        with open(norm_path, "rb") as f:
            if config.partial_hash:
                chunk = f.read(DEFAULT_CHUNK_SIZE)
                if not chunk:
                    return file_path, ""  # Empty file hash
                hasher.update(chunk)
            else:
                while chunk := f.read(DEFAULT_CHUNK_SIZE):
                    hasher.update(chunk)
        return file_path, hasher.hexdigest()
    except (OSError, IOError) as e:
        logging.warning(f"Could not hash file {file_path}: {e}")
        return file_path, None
    except Exception as e:
        logging.error(f"Unexpected error hashing {file_path}: {e}")
        return file_path, None


def find_potential_duplicates_by_size(
        config: Config,
) -> Dict[int, List[str]]:
    """Scans directory and groups files by size."""
    files_by_size = collections.defaultdict(list)
    print(
        f"\nScanning directory: {config.directory} for files >= {config.min_size} bytes..."
    )
    count = 0
    skipped_unreadable = 0
    for root, _, files in os.walk(config.directory, topdown=True):
        if count % 5000 == 0 and count > 0:
            print(f"  ...scanned {count} files", end="\r")

        for filename in files:
            file_path = os.path.join(root, filename)
            norm_path = normalize_path(file_path, config)
            try:
                # Use lstat to handle symlinks correctly
                stat_info = os.lstat(norm_path)
                if not os.path.isfile(norm_path):
                    continue
                file_size = stat_info.st_size
                if file_size >= config.min_size:
                    files_by_size[file_size].append(file_path)
                    count += 1
            except FileNotFoundError:
                logging.debug(f"File vanished during scan: {file_path}")
            except OSError as e:
                logging.warning(f"Could not access {file_path}: {e}")
                skipped_unreadable += 1

    print(f"  ...scanned {count} files total.                 ")
    if skipped_unreadable > 0:
        print(
            f"Skipped {skipped_unreadable} unreadable files/directories."
        )

    potential_duplicates = {
        size: paths
        for size, paths in files_by_size.items()
        if len(paths) > 1
    }
    print(
        f"Found {len(potential_duplicates)} sizes with potential duplicates."
    )
    return potential_duplicates


def identify_hardlinks(
        potential_groups: Dict[int, List[str]], config: Config
) -> Tuple[Dict[int, List[str]], Dict[Tuple[int, int], List[str]], int]:
    """Identifies hardlinks within size groups."""
    print("Checking for hardlinks...")
    hardlinks_found: Dict[
        Tuple[int, int], List[str]
    ] = collections.defaultdict(list)
    groups_to_check = {}
    hardlink_space = 0
    processed_files = 0
    total_files = sum(len(paths) for paths in potential_groups.values())

    for size, paths in potential_groups.items():
        files_by_id = collections.defaultdict(list)
        for path in paths:
            processed_files += 1
            if processed_files % 100 == 0:
                print(
                    f"  ...checking hardlink {processed_files}/{total_files}",
                    end="\r",
                )
            norm_path = normalize_path(path, config)
            file_id = get_file_id(norm_path)
            if file_id:
                files_by_id[file_id].append(path)

        remaining_paths = []
        for file_id, linked_paths in files_by_id.items():
            if len(linked_paths) > 1:
                hardlinks_found[file_id].extend(linked_paths)
                hardlink_space += size * (len(linked_paths) - 1)
            else:
                remaining_paths.extend(linked_paths)

        # Handle files where ID could not be retrieved
        paths_without_id = [
            p
            for p in paths
            if get_file_id(normalize_path(p, config)) is None
        ]
        remaining_paths.extend(paths_without_id)

        if len(remaining_paths) > 1:
            groups_to_check[size] = remaining_paths

    print(
        f"Hardlink check complete. Found {len(hardlinks_found)} sets.          "
    )
    if hardlink_space > 0:
        print(f"Space shared by hardlinks: {format_bytes(hardlink_space)}")

    return groups_to_check, hardlinks_found, hardlink_space


def identify_duplicates_by_hash(
        groups_to_check: Dict[int, List[str]], config: Config
) -> Dict[str, List[str]]:
    """Identifies duplicates by hashing files."""
    if not groups_to_check:
        return {}

    print(
        f"\nStarting hash comparison (Algorithm: {config.hash_algo}, "
        f"Partial Check: {config.partial_hash})..."
    )
    duplicates: Dict[str, List[str]] = collections.defaultdict(list)
    files_to_hash_full = []

    # --- Stage 1: Partial Hashing (if enabled) ---
    if config.partial_hash:
        print("Performing partial hash check...")
        files_to_hash_partial = [
            (path, config)
            for paths in groups_to_check.values()
            for path in paths
        ]
        print(
            f"Hashing (partial) {len(files_to_hash_partial)} files using "
            f"{config.workers} workers..."
        )

        partial_hashes: Dict[str, Optional[str]] = {}
        with Pool(processes=config.workers) as pool:
            results = pool.map(compute_hash_worker, files_to_hash_partial)
            for path, h in results:
                partial_hashes[path] = h

        potential_full_hash_groups = collections.defaultdict(list)
        for size, paths in groups_to_check.items():
            for path in paths:
                phash = partial_hashes.get(path)
                if phash is not None:
                    potential_full_hash_groups[(size, phash)].append(path)

        for (size, phash), paths in potential_full_hash_groups.items():
            if len(paths) > 1:
                files_to_hash_full.extend(paths)
        print(
            f"Partial hash check complete. Identified {len(files_to_hash_full)} "
            f"files needing full hash."
        )
    else:
        files_to_hash_full = [
            path for paths in groups_to_check.values() for path in paths
        ]
        print(
            f"Full hash check needed for {len(files_to_hash_full)} files."
        )

    # --- Stage 2: Full Hashing ---
    if not files_to_hash_full:
        print("No files require full hashing.")
        return {}

    print(
        f"Performing full hash check on {len(files_to_hash_full)} files using "
        f"{config.workers} workers..."
    )
    # Temporarily disable partial hash for the full run
    original_partial_setting = config.partial_hash
    config.partial_hash = False
    files_to_hash_args = [(path, config) for path in files_to_hash_full]

    final_hashes: Dict[str, Optional[str]] = {}
    with Pool(processes=config.workers) as pool:
        results = pool.map(compute_hash_worker, files_to_hash_args)
        for path, h in results:
            final_hashes[path] = h
    config.partial_hash = original_partial_setting  # Restore setting

    files_by_full_hash = collections.defaultdict(list)
    for path, full_hash in final_hashes.items():
        if full_hash:
            files_by_full_hash[full_hash].append(path)

    for full_hash, paths in files_by_full_hash.items():
        if len(paths) > 1:
            duplicates[full_hash] = paths

    print(
        f"Hash comparison complete. Found {len(duplicates)} sets of duplicate files."
    )
    return duplicates


# --- Action and Reporting Functions ---
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
                            win32file.CreateHardLink(
                                norm_process_path, norm_keep_path
                            )
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


def generate_report(
    duplicates: Dict, hardlinks: Dict, config: Config
) -> str:
    """Generates a report file in the specified format."""
    if not config.enable_reports:
        return ""

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_filename = os.path.join(
        config.report_path,
        f"CloneReaper-Report-{timestamp}.{config.report_format}",
    )
    print(f"\nGenerating {config.report_format.upper()} report...")

    report_data = {
        "scan_time": timestamp,
        "scan_directory": config.directory,
        "duplicates": duplicates,
        "hardlinks": hardlinks,
    }

    try:
        # --- THIS IS THE FIX ---
        # Open with UTF-8 encoding to handle special characters in filenames
        with open(report_filename, "w", encoding="utf-8", newline="") as f:
            if config.report_format == "json":
                # Add ensure_ascii=False to write characters like '♡' directly
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            elif config.report_format == "csv":
                writer = csv.writer(f)
                writer.writerow(
                    ["Type", "Identifier", "Size (Bytes)", "File Path"]
                )
                for hash_val, paths in duplicates.items():
                    size = os.path.getsize(paths[0])
                    for path in paths:
                        writer.writerow(["Duplicate", hash_val[:12], size, path])
                for id_val, paths in hardlinks.items():
                    size = os.path.getsize(paths[0])
                    for path in paths:
                        writer.writerow(["Hardlink", id_val, size, path])
            else:  # txt
                f.write("--- CloneReaper Scan Report ---\n")
                f.write(f"Time: {timestamp}\n")
                f.write(f"Directory: {config.directory}\n")
                f.write("\n--- Duplicates ---\n")
                for hash_val, paths in duplicates.items():
                    size = format_bytes(os.path.getsize(paths[0]))
                    f.write(f"Hash: {hash_val[:12]}... ({size})\n")
                    for path in paths:
                        f.write(f"  - {path}\n")
                f.write("\n--- Hardlinks ---\n")
                for id_val, paths in hardlinks.items():
                    size = format_bytes(os.path.getsize(paths[0]))
                    f.write(f"ID: {id_val} ({size})\n")
                    for path in paths:
                        f.write(f"  - {path}\n")
        print(f"Report saved to: {report_filename}")
        return report_filename
    except IOError as e:
        logging.error(f"Could not write report file: {e}")
        return ""


def send_email_report(report_path: str, config: Config):
    """Sends the generated report via email."""
    if not config.email_config.get("enabled") or not report_path:
        return

    cfg = config.email_config
    # Let's add a more robust check for empty values, not just missing keys
    if not all(cfg.get(k) for k in ["server", "port", "user", "password", "recipient"]):
        print("Email configuration is incomplete (some values are empty). Skipping email.")
        return

    print(f"Preparing to send email report to {cfg['recipient']}...")

    try:
        msg = MIMEMultipart()
        msg["From"] = cfg["user"]
        msg["To"] = cfg["recipient"]
        msg["Subject"] = f"CloneReaper Scan Report - {time.strftime('%Y-%m-%d')}"

        body = "Please find the CloneReaper scan report attached."
        msg.attach(MIMEText(body, "plain"))

        with open(report_path, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={os.path.basename(report_path)}",
        )
        msg.attach(part)

        with smtplib.SMTP(cfg["server"], cfg["port"]) as server:
            # --- THIS IS THE KEY DIAGNOSTIC LINE ---
            # server.set_debuglevel(1)  # Print the full SMTP conversation

            server.starttls()
            server.login(cfg["user"], cfg["password"])
            server.send_message(msg)

        print("Email report sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        print(f"Error: Failed to send email. Check logs for details.")


def trigger_media_server_scan(config: Config):
    """Triggers a library scan on configured media servers."""
    if not config.media_server_config.get("enabled"):
        return

    print("Media server integration is enabled (implementation pending).")
    print(
        "You would configure server URLs and API keys for Plex/Jellyfin/Emby."
    )
    # Example using requests library:
    # import requests
    #
    # for server in config.media_server_config.get('servers', []):
    #     if server['type'] == 'plex':
    #         url = f"{server['url']}/library/sections/all/refresh?X-Plex-Token={server['api_key']}"
    #         try:
    #             requests.get(url)
    #             print(f"Triggered Plex scan on {server['url']}")
    #         except requests.RequestException as e:
    #             logging.error(f"Failed to trigger Plex scan: {e}")


# --- Interactive UI Functions ---
def ask_yes_no(prompt: str, default_yes: bool = False) -> bool:
    """Asks a yes/no question."""
    suffix = "(Y/n)" if default_yes else "(y/N)"
    while True:
        response = input(f"{prompt} {suffix}: ").strip().lower()
        if not response:
            return default_yes
        if response in ["y", "yes"]:
            return True
        if response in ["n", "no"]:
            return False
        print("Invalid input. Please enter 'yes' or 'no'.")

def configure_email(config: Config):
    """Interactive sub-menu for configuring email settings."""
    print("\n--- Configure Email Settings ---")
    print("Note: For Gmail, you may need to use an 'App Password'.")
    config.email_config["enabled"] = ask_yes_no(
        "Enable email reports?", config.email_config.get("enabled", False)
    )
    if not config.email_config["enabled"]:
        return

    cfg = config.email_config
    cfg["server"] = input(
        f"SMTP Server [{cfg.get('server', 'smtp.gmail.com')}]: "
    ).strip() or cfg.get("server", "smtp.gmail.com")
    cfg["port"] = int(
        input(f"SMTP Port [{cfg.get('port', 587)}]: ").strip()
        or cfg.get("port", 587)
    )
    cfg["user"] = input(f"SMTP Username (your email) [{cfg.get('user', '')}]: ").strip() or cfg.get("user", "")
    cfg["password"] = input("SMTP Password or App Password: ").strip()
    cfg["recipient"] = input(
        f"Recipient Email [{cfg.get('recipient', cfg.get('user', ''))}]: "
    ).strip() or cfg.get("recipient", cfg.get("user", ""))

def get_choice(prompt: str, options: List[str]) -> int:
    """Gets a numbered choice from a list of options."""
    for i, option in enumerate(options):
        print(f"  {i + 1}. {option}")
    while True:
        try:
            choice = input(f"{prompt} (1-{len(options)}): ").strip()
            index = int(choice) - 1
            if 0 <= index < len(options):
                return index
            else:
                print("Invalid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def configure_scan(config: Config):
    """Interactive sub-menu for configuring scan settings."""
    print("\n--- Configure Scan Settings ---")
    # Directory
    while True:
        path = input(
            f"Enter the directory path to scan [{config.directory or 'not set'}]: "
        ).strip()
        if not path and config.directory:
            break
        if os.path.isdir(path):
            config.directory = path
            break
        else:
            print(f"Error: '{path}' is not a valid directory.")

    # Min Size
    while True:
        try:
            size_str = input(
                f"Minimum file size in bytes [{config.min_size}]: "
            ).strip()
            if not size_str:
                break
            min_size = int(size_str)
            if min_size >= 0:
                config.min_size = min_size
                break
            else:
                print("Minimum size cannot be negative.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Hash Algorithm
    available_algos = sorted(list(hashlib.algorithms_available))
    print("Available hash algorithms:")
    for i, algo in enumerate(available_algos):
        print(f"  {i+1}. {algo}", end="  ")
        if (i + 1) % 5 == 0:
            print()
    print()
    while True:
        algo_choice = input(
            f"Choose hash algorithm number or name [{config.hash_algo}]: "
        ).strip()
        if not algo_choice:
            break
        try:
            index = int(algo_choice) - 1
            if 0 <= index < len(available_algos):
                config.hash_algo = available_algos[index]
                break
            else:
                print("Invalid number.")
        except ValueError:
            if algo_choice in available_algos:
                config.hash_algo = algo_choice
                break
            else:
                print(f"Invalid algorithm name '{algo_choice}'.")

    # Other toggles
    config.partial_hash = ask_yes_no(
        "Use partial hash pre-check (faster)?", config.partial_hash
    )
    if platform.system() == "Windows":
        config.long_paths_enabled = ask_yes_no(
            "Enable Windows long path support?", config.long_paths_enabled
        )
    config.verbose_logging = ask_yes_no(
        "Enable verbose logging?", config.verbose_logging
    )
    setup_logging(logging.DEBUG if config.verbose_logging else logging.INFO)


def configure_actions(config: Config):
    """Interactive sub-menu for configuring action settings."""
    print("\n--- Configure Action Settings ---")
    config.dry_run = ask_yes_no(
        "Run in Dry Run mode (no files changed)?", config.dry_run
    )

    print("Choose action for duplicates:")
    action_options = [
        "None (report only)",
        "Safe Delete (move to Quarantine)",
        "Permanent Delete",
        "Replace with Hardlinks",
    ]
    action_map = ["none", "quarantine", "delete", "link"]
    choice_idx = get_choice("Select action", action_options)
    config.action_mode = action_map[choice_idx]

    if config.action_mode != "none":
        print("Choose which file to KEEP in each duplicate set:")
        strategy_options = ["first", "oldest", "newest", "shortest", "longest"]
        strategy_idx = get_choice("Select keep strategy", strategy_options)
        config.keep_strategy = strategy_options[strategy_idx]

    if config.action_mode == "quarantine":
        default_q_path = os.path.join(
            config.directory or ".", QUARANTINE_FOLDER_NAME
        )
        q_path = input(
            f"Enter quarantine path [{default_q_path}]: "
        ).strip()
        config.quarantine_path = q_path or default_q_path

    if config.action_mode == "delete":
        print("Deletion is permanent and cannot be undone.")
        config.confirmations = 3 if ask_yes_no(
            "Enable TRIPLE confirmation for deletion?", True
        ) else 2


def configure_reporting(config: Config):
    """Interactive sub-menu for configuring reporting."""
    print("\n--- Configure Reporting & Integrations ---")
    config.enable_reports = ask_yes_no(
        "Generate a report file?", config.enable_reports
    )
    if config.enable_reports:
        report_options = ["txt", "json", "csv"]
        choice_idx = get_choice("Select report format", report_options)
        config.report_format = report_options[choice_idx]

    # Placeholder for email/media server config
    config.email_config["enabled"] = ask_yes_no(
        "Enable email reports (requires setup)?",
        config.email_config["enabled"],
    )
    config.media_server_config["enabled"] = ask_yes_no(
        "Enable Media Server integration (requires setup)?",
        config.media_server_config["enabled"],
    )


def display_banner():
    """Displays the application banner."""
    banner = r"""
 ██████╗██╗      ██████╗ ███╗   ██╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗     ██████╗ ██████╗ ██╗███╗   ███╗███████╗
██╔════╝██║     ██╔═══██╗████╗  ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝
██║     ██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝    ██████╔╝██████╔╝██║██╔████╔██║█████╗  
██║     ██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗    ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝  
╚██████╗███████╗╚██████╔╝██║ ╚████║███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║    ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗
 ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝
                                                                                                                                     
"""
    print(banner)


def display_summary(config: Config):
    """Prints a summary of the current configuration."""
    print("\n--- Configuration Summary ---")
    print(f"  Scan Path:         {config.directory or 'Not Set'}")
    print(f"  Min File Size:     {config.min_size} bytes")
    print(f"  Action:            {config.action_mode.capitalize()}")
    if config.action_mode != "none":
        print(f"  Keep Strategy:     {config.keep_strategy.capitalize()}")
        print(f"  Dry Run:           {'YES' if config.dry_run else 'NO'}")
    print(f"  Reporting:         {'Enabled' if config.enable_reports else 'Disabled'}")
    if config.enable_reports:
        print(f"  Report Format:     {config.report_format.upper()}")
    print("-----------------------------")


def run_scan_and_process(config: Config):
    """The main workflow for scanning and processing."""
    if not config.directory:
        print("\nError: Scan directory is not set. Please configure it first.")
        return

    start_time = time.time()
    duplicates, hardlinks = {}, {}

    if config.import_report_path:
        print(f"Loading results from report: {config.import_report_path}")
        try:
            with open(config.import_report_path, "r") as f:
                report_data = json.load(f)
                duplicates = report_data.get("duplicates", {})
                hardlinks = report_data.get("hardlinks", {})
            print("Successfully loaded results from report.")
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error loading report: {e}. Aborting.")
            return
    else:
        # 1. Find by size
        potential_groups = find_potential_duplicates_by_size(config)

        # 2. Filter hardlinks
        groups_to_hash = potential_groups
        if config.check_hardlinks:
            groups_to_hash, hardlinks, _ = identify_hardlinks(
                potential_groups, config
            )

        # 3. Find by hash
        duplicates = identify_duplicates_by_hash(groups_to_hash, config)

    # 4. Display results
    print("\n--- Scan Results ---")
    if not duplicates and not hardlinks:
        print("No duplicate files or hardlinks found.")
    else:
        if hardlinks:
            print("\nHardlinks Found (sharing space, not true duplicates):")
            for file_id, paths in hardlinks.items():
                size = format_bytes(os.path.getsize(paths[0]))
                print(f"  ID: {file_id} ({len(paths)} links, Size: {size})")
        if duplicates:
            wasted_space = calculate_wasted_space(duplicates, config)
            print("\nDuplicate Files Found:")
            print(
                f"(Total potential space savings: {format_bytes(wasted_space)})"
            )
            for file_hash, paths in duplicates.items():
                size = format_bytes(os.path.getsize(paths[0]))
                print(
                    f"  Hash: {file_hash[:12]}... ({len(paths)} files, Size: {size})"
                )

    # 5. Generate Report
    report_path = generate_report(duplicates, hardlinks, config)

    # 6. Perform Actions
    if duplicates and config.action_mode != "none":
        final_confirm = True
        if not config.dry_run:
            wasted_space = calculate_wasted_space(duplicates, config)
            num_files = sum(len(v) - 1 for v in duplicates.values())
            print("\n--- FINAL CONFIRMATION ---")
            for i in range(config.confirmations):
                prompt = (
                    f"Really {config.action_mode} {num_files} files "
                    f"({format_bytes(wasted_space)})? This cannot be undone."
                )
                if not ask_yes_no(prompt, False):
                    final_confirm = False
                    break

        if final_confirm:
            processed_count, saved_size = perform_actions(duplicates, config)
            action_type = "processed" if config.dry_run else "completed"
            print(
                f"\nAction {action_type}. "
                f"Files processed: {processed_count}. "
                f"Space saved/recovered: {format_bytes(saved_size)}."
            )
            # Trigger integrations after action
            if not config.dry_run:
                send_email_report(report_path, config)
                trigger_media_server_scan(config)
        else:
            print("Action cancelled by user.")

    end_time = time.time()
    print(f"\nOperation finished in {end_time - start_time:.2f} seconds.")


def main_interactive():
    """Main function to run the interactive menu."""
    # Define the config file path at the top
    CONFIG_FILE = "clonereaper_config.json"

    # Load the config at the very start
    config = Config.load(CONFIG_FILE)

    setup_logging(logging.DEBUG if config.verbose_logging else logging.INFO)
    display_banner()
    print("Welcome to CloneReaper Prime! An advanced duplicate file manager with email reporting.")

    # The main loop remains mostly the same
    while True:
        display_summary(config)
        menu_options = [
            "Configure Scan Settings",
            "Configure Actions (Delete, Quarantine, Link)",
            "Configure Reporting",
            "Configure Email & Integrations",
            "RUN SCAN from configured path",
            "IMPORT REPORT and run actions",
            "Exit",
        ]
        # Adjust the choice numbers based on the new menu length
        choice = get_choice("\nMain Menu", menu_options)

        if choice == 0:
            configure_scan(config)
        elif choice == 1:
            configure_actions(config)
        elif choice == 2:
            configure_reporting(config)
        elif choice == 3:
            configure_email(config)
        elif choice == 4:
            config.import_report_path = None
            run_scan_and_process(config)
        elif choice == 5:
            path = input("Enter the path to the JSON report file: ").strip()
            if os.path.isfile(path):
                config.import_report_path = path
                run_scan_and_process(config)
            else:
                print(f"Error: '{path}' is not a valid file.")
        elif choice == 6:  # Exit
            # --- THIS IS THE FIX ---
            # Save the configuration before exiting
            config.save(CONFIG_FILE)
            print("Configuration saved. Exiting CloneReaper Prime. Goodbye!")
            break


def main():
    """Main entry point, handles command-line args or launches interactive mode."""
    parser = argparse.ArgumentParser(
        description="CloneReaper: Find and manage duplicate files.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "directory",
        nargs="?",
        help="The directory to scan. If omitted, interactive mode starts.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Run without prompts. Requires other flags to be set.",
    )
    parser.add_argument(
        "--action",
        choices=["delete", "quarantine", "link", "none"],
        default="none",
        help="Action to perform on duplicates.",
    )
    parser.add_argument(
        "--report-format",
        choices=["json", "csv", "txt"],
        help="Generate a report in the specified format.",
    )
    parser.add_argument(
        "--import-report",
        help="Import a JSON report to perform actions on, skipping the scan.",
    )
    # Add more arguments to mirror all Config options as needed
    # e.g., --min-size, --keep-strategy, --dry-run, etc.

    args = parser.parse_args()

    if not args.directory and not args.import_report:
        main_interactive()
    else:
        # Non-interactive / automated run
        if not args.non_interactive:
            print(
                "Warning: Running from command line without --non-interactive."
            )
            if not ask_yes_no("Proceed?", True):
                sys.exit(0)

        config = Config()
        config.directory = args.directory
        config.action_mode = args.action
        config.dry_run = False  # Default to active mode for automation
        config.import_report_path = args.import_report

        if args.report_format:
            config.enable_reports = True
            config.report_format = args.report_format

        print("--- Running in Non-Interactive Mode ---")
        display_summary(config)
        run_scan_and_process(config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)