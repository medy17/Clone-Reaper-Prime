# CloneReaper Prime

CloneReaper Prime is an advanced, cross-platform duplicate file finder and manager written in Python. It's designed to be both powerful for automated tasks and safe and easy to use through its interactive menu. Find duplicate files, recover precious disk space, and manage your data with confidence.

## Key Features

-   [x] **High-Performance Scanning:** Uses parallel processing (`multiprocessing`) to hash files and find duplicates quickly, especially on multi-core systems.
-   [x] **Email Notifications:** Configure SMTP settings to have scan reports automatically emailed to you upon completion. Guided setup for first time users.
-   [x] **Efficient Two-Stage Scan:** First identifies files of the same size, then only hashes those potential duplicates, saving significant time.
-   [x] **Safety First Approach:**
    -   **Dry Run Mode:** See what changes would be made without touching a single file.
    -   **Safe Quarantine:** Move duplicates to a quarantine folder for review instead of deleting them permanently.
    -   **Multiple Confirmations:** Requires double or triple confirmation for permanent deletion.
-   [x] **Intelligent Hardlink Support:**
    -   Correctly detects hardlinked files on both **Windows (NTFS)** and **Linux/macOS**.
    -   Can replace duplicate files with hardlinks to save space without altering your directory structure—perfect for media libraries!
-   [x] **Flexible & User-Friendly:**
    -   **Interactive Menu:** An easy-to-navigate menu system for configuration and execution.
    -   **Command-Line Mode:** Supports arguments for automation and scripting (e.g., weekly `cron` jobs or scheduled tasks).
-   [x] **Persistent Configuration:** Automatically saves your settings (paths, email config, etc.) to a `clonereaper_config.json` file so you don't have to re-enter them every time.
-   [x] **Comprehensive Reporting:**
    -   Generate detailed reports of duplicates and hardlinks in **JSON**, **CSV**, or plain **TXT** format.
    -   Import a previous JSON report to perform actions later, separating the scanning and cleaning phases.

## Installation

CloneReaper Prime is designed to be simple to set up.

1.  **Prerequisites:**
    -   Python 3.8 or newer.

2.  **Clone the repository:**
    ```bash
    git clone https://github.com/medy17/Clone_Reaper-Prime.git
    cd Clone-Reaper-Prime
    ```

3.  **Install dependencies:**
    The only external dependency is `pywin32` for Windows-specific features. The included `requirements.txt` file handles this automatically.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

You can run CloneReaper Prime in two modes: Interactive (recommended for first-time use) or Non-Interactive (for automation).

### Interactive Mode

Simply run the script without any arguments to launch the full menu-driven interface.

```bash
python CloneReaperPrimeProd.py
```

You will be guided through a series of menus to:
1.  **Configure Scan Settings:** Set the target directory, minimum file size, and hashing algorithm.
2.  **Configure Actions:** Choose what to do with duplicates (Quarantine, Delete, Link) and enable Dry Run mode.
3.  **Configure Reporting & Email:** Set up report generation and email notifications.
4.  **Run the Scan:** Execute the scan and review the results.
5.  **Perform Actions:** If not in Dry Run mode, confirm and perform the chosen actions on the found duplicates.

### Non-Interactive / Automated Mode

CloneReaper Prime can be run from the command line, making it perfect for scheduled tasks.

**Example:** Scan a directory, permanently delete duplicates, and generate a JSON report.

```bash
python CloneReaperPrimeProd.py /path/to/your/media --non-interactive --action delete --report-format json
```

> **Note:** When using `--non-interactive`, the script will not ask for confirmation. Use with caution!

## Configuration File

The first time you exit the interactive menu, CloneReaper Prime will create a `clonereaper_config.json` file in the same directory. This file stores all your settings, so they are automatically loaded the next time you start the script.

You can edit this file directly if you prefer, but it's generally safer to manage settings through the interactive menu.

**Example `clonereaper_config.json`:**
```json
{
  "directory": "D:/Jellyfin/Movies",
  "min_size": 1,
  "hash_algo": "sha256",
  "action_mode": "quarantine",
  "dry_run": false,
  "email_config": {
    "enabled": true,
    "server": "smtp.gmail.com",
    "port": 587,
    "user": "your-email@gmail.com",
    "password": "your-app-password",
    "recipient": "your-email@gmail.com"
  }
}
```

## ⚠️ A Note on Safety

This is a powerful tool that can delete a large number of files. Please follow these best practices:

1.  **Always run in `Dry Run` mode first.** This will show you exactly which files are identified as duplicates without making any changes.
2.  **Use the `Quarantine` action** instead of `Permanent Delete` for your first few runs. This moves files to a safe folder, allowing you to verify them and recover any that were incorrectly identified.
3.  **Double-check your target directory.** Make sure you are not scanning a system directory or a folder synced with a cloud service that might have its own versioning system.
4.  **Backup your data.** Before running any large-scale file operation, ensure you have a reliable backup.

## Contributing

Contributions are welcome! If you have an idea for a new feature or have found a bug, please feel free to:
1.  Open an issue to discuss the change.
2.  Fork the repository and submit a pull request.

## License

This project is licensed under the CC BY-NC-SA License. See the `LICENSE` file for details.
