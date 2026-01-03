import csv
import json
import logging
import os
import smtplib
import time
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List

from .config import Config
from .utils import format_bytes


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
