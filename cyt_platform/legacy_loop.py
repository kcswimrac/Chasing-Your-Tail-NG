### Chasing Your Tail V04_15_22
### @matt0177
### Released under the MIT License https://opensource.org/licenses/MIT
###
### The original in-memory-only monitoring loop (no CytStore / status.json).
### Canonical home since the legacy quarantine (locked decision 2): the
### platform ships this as its ``--legacy-loop`` compat path. The historical
### ``chasing_your_tail.py`` entry now lives in ``legacy/`` and dispatches
### here.

import glob
import logging
import os
import pathlib
import signal
import sys
import time

from cyt_platform.secure_credentials import secure_config_loader
from cyt_platform.secure_database import SecureKismetDB
from cyt_platform.secure_ignore_loader import load_ignore_lists
from cyt_platform.secure_main_logic import SecureCYTMonitor


def run_legacy_loop() -> int:
    """Original monitoring loop without CytStore (compat / lab)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("cyt_security.log"),
            logging.StreamHandler(),
        ],
    )

    config, credential_manager = secure_config_loader("config.json")
    logging.info("Configuration loaded with secure credential management")

    cyt_sub = pathlib.Path(config["paths"]["log_dir"])
    cyt_sub.mkdir(parents=True, exist_ok=True)

    print("Current Time: " + time.strftime("%Y-%m-%d %H:%M:%S"))
    print("Running LEGACY loop (no CytStore / no status.json)")

    log_file_name = f'./logs/cyt_log_{time.strftime("%m%d%y_%H%M%S")}'
    cyt_log = open(log_file_name, "w", buffering=1)

    ignore_list, probe_ignore_list = load_ignore_lists(config)
    print(f"{len(ignore_list)} MACs added to ignore list.")
    print(f"{len(probe_ignore_list)} Probed SSIDs added to ignore list.")
    cyt_log.write(f"{len(ignore_list)} MACs added to ignore list.\n")
    cyt_log.write(f"{len(probe_ignore_list)} Probed SSIDs added to ignore list.\n")

    db_path = config["paths"]["kismet_logs"]
    try:
        list_of_files = glob.glob(db_path)
        if not list_of_files:
            raise FileNotFoundError(f"No Kismet database files found at: {db_path}")

        latest_file = max(list_of_files, key=os.path.getctime)
        print(f"Pulling data from: {latest_file}")
        cyt_log.write(f"Pulling data from: {latest_file}\n")

        secure_monitor = SecureCYTMonitor(config, ignore_list, probe_ignore_list, cyt_log)

        with SecureKismetDB(latest_file) as db:
            if not db.validate_connection():
                raise RuntimeError("Database validation failed")
            print("Initializing secure tracking lists...")
            secure_monitor.initialize_tracking_lists(db)
            print("Initialization complete!")
    except Exception as e:
        error_msg = f"Fatal error during initialization: {e}"
        print(error_msg)
        cyt_log.write(f"{error_msg}\n")
        logging.error(error_msg)
        return 1

    def signal_handler(signum, frame):
        print("\nShutting down gracefully...")
        cyt_log.write("Shutting down gracefully...\n")
        logging.info("CYT monitoring stopped by user")
        cyt_log.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    time_count = 0
    check_interval = config.get("timing", {}).get("check_interval", 60)
    list_update_interval = config.get("timing", {}).get("list_update_interval", 5)

    logging.info("Starting secure CYT monitoring loop...")
    print("🔒 SECURE MODE: All SQL injection vulnerabilities have been eliminated!")
    print(
        f"Monitoring every {check_interval} seconds, "
        f"updating lists every {list_update_interval} cycles"
    )

    while True:
        time_count += 1
        try:
            with SecureKismetDB(latest_file) as db:
                secure_monitor.process_current_activity(db)
                if time_count % list_update_interval == 0:
                    logging.info(f"Rotating tracking lists (cycle {time_count})")
                    secure_monitor.rotate_tracking_lists(db)
        except Exception as e:
            error_msg = f"Error in monitoring loop: {e}"
            print(error_msg)
            cyt_log.write(f"{error_msg}\n")
            logging.error(error_msg)
            continue
        time.sleep(check_interval)
