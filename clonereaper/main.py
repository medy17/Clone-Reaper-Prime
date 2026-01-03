import argparse
import json
import logging
import os
import sys
import time
from typing import Dict

from .config import Config
from .utils import setup_logging, format_bytes
from .scanner import find_potential_duplicates_by_size, identify_hardlinks, identify_duplicates_by_hash
from .actions import calculate_wasted_space, perform_actions
from .reporting import generate_report, send_email_report
from .integrations import trigger_media_server_scan

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

            # Interactive confirmation prompt if not in non-interactive mode
            # But here we are in the core logic.
            # If we are running from UI, we might want to prompt.
            # If we are running from CLI non-interactive, we shouldn't prompt (already handled).
            # The prompt logic was embedded here in the original code.

            # To preserve behavior, we need a way to ask user confirmation.
            # But this module shouldn't depend on UI.
            # However, for simplicity of migration, I will import ask_yes_no locally if needed
            # or rely on a callback/config.

            # Refactoring: we'll assume if it's CLI automated, confirmations is handled or ignored?
            # Original code:
            # for i in range(config.confirmations):
            #    if not ask_yes_no(prompt, False): ...

            # I will implement a simple confirmation mechanism here that uses input()
            # If we want to strictly separate UI, this should be passed as a callback.
            # For now, I'll use input() as it was in the original script.

            for i in range(config.confirmations):
                prompt = (
                    f"Really {config.action_mode} {num_files} files "
                    f"({format_bytes(wasted_space)})? This cannot be undone."
                )
                # We need to import ask_yes_no here or duplicate it.
                # To avoid circular import, let's duplicate simple input logic or move ask_yes_no to utils.
                # I'll move ask_yes_no to utils later or just implement simple input here.

                suffix = "(y/N)"
                response = input(f"{prompt} {suffix}: ").strip().lower()
                if response not in ["y", "yes"]:
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
    parser.add_argument(
        "--file-patterns",
        nargs="+",
        help="Include/Exclude file patterns (e.g. *.jpg !*.tmp)",
    )

    args = parser.parse_args()

    if not args.directory and not args.import_report:
        from .ui import main_interactive
        main_interactive()
    else:
        # Non-interactive / automated run
        if not args.non_interactive:
            print(
                "Warning: Running from command line without --non-interactive."
            )
            # Simple yes/no
            response = input("Proceed? (y/N): ").strip().lower()
            if response not in ["y", "yes"]:
                sys.exit(0)

        config = Config()
        config.directory = args.directory
        config.action_mode = args.action
        config.dry_run = False  # Default to active mode for automation
        config.import_report_path = args.import_report
        if args.file_patterns:
            config.file_patterns = args.file_patterns

        if args.report_format:
            config.enable_reports = True
            config.report_format = args.report_format

        print("--- Running in Non-Interactive Mode ---")
        # display_summary is in ui.py, but we can print basic info here or import it
        print(f"Scan Path: {config.directory}")
        print(f"Action: {config.action_mode}")
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
