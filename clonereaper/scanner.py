import collections
import hashlib
import logging
import os
import fnmatch
from multiprocessing import Pool
from typing import Dict, List, Optional, Tuple

from .config import Config, DEFAULT_CHUNK_SIZE
from .utils import normalize_path, get_file_id

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

def match_patterns(filename: str, patterns: List[str]) -> bool:
    """
    Checks if filename matches any of the patterns.
    If patterns list is empty, matches everything.
    If patterns has entries starting with !, they are exclusions.
    """
    if not patterns:
        return True

    # Separate include and exclude patterns
    includes = [p for p in patterns if not p.startswith('!')]
    excludes = [p[1:] for p in patterns if p.startswith('!')]

    # If there are include patterns, the file must match at least one
    matched_include = False
    if not includes:
        matched_include = True # If no include patterns, everything is included by default (unless excluded)
    else:
        for p in includes:
            if fnmatch.fnmatch(filename, p):
                matched_include = True
                break

    if not matched_include:
        return False

    # If the file matches an exclude pattern, return False
    for p in excludes:
        if fnmatch.fnmatch(filename, p):
            return False

    return True

def find_potential_duplicates_by_size(
        config: Config,
) -> Dict[int, List[str]]:
    """Scans directory and groups files by size."""
    files_by_size = collections.defaultdict(list)
    print(
        f"\nScanning directory: {config.directory} for files >= {config.min_size} bytes..."
    )
    if config.file_patterns:
         print(f"Applying file patterns: {config.file_patterns}")

    count = 0
    skipped_unreadable = 0
    for root, _, files in os.walk(config.directory, topdown=True):
        if count % 5000 == 0 and count > 0:
            print(f"  ...scanned {count} files", end="\r")

        for filename in files:
            if not match_patterns(filename, config.file_patterns):
                continue

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
