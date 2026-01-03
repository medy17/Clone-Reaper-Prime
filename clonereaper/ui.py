import hashlib
import logging
import os
import platform
from typing import List

from .config import Config, QUARANTINE_FOLDER_NAME
from .utils import setup_logging
from .main import run_scan_and_process

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

    # File Patterns
    print(f"Current File Patterns: {config.file_patterns or 'All files'}")
    if ask_yes_no("Configure file patterns (include/exclude)?"):
        patterns_str = input("Enter patterns separated by space (e.g. *.jpg !*.tmp): ").strip()
        if patterns_str:
            config.file_patterns = patterns_str.split()
        else:
            config.file_patterns = []


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
    print(f"  File Patterns:     {config.file_patterns or 'All files'}")
    print(f"  Action:            {config.action_mode.capitalize()}")
    if config.action_mode != "none":
        print(f"  Keep Strategy:     {config.keep_strategy.capitalize()}")
        print(f"  Dry Run:           {'YES' if config.dry_run else 'NO'}")
    print(f"  Reporting:         {'Enabled' if config.enable_reports else 'Disabled'}")
    if config.enable_reports:
        print(f"  Report Format:     {config.report_format.upper()}")
    print("-----------------------------")


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
            # Save the configuration before exiting
            config.save(CONFIG_FILE)
            print("Configuration saved. Exiting CloneReaper Prime. Goodbye!")
            break
