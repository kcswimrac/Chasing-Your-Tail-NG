# Chasing Your Tail (CYT)

A comprehensive Wi-Fi probe request analyzer that monitors and tracks wireless devices by analyzing their probe requests. The system integrates with Kismet for packet capture and WiGLE API for SSID geolocation analysis, featuring advanced surveillance detection capabilities.

## 🚨 Security Notice

This project has been security-hardened to eliminate critical vulnerabilities:
- **SQL injection prevention** with parameterized queries
- **Encrypted credential management** for API keys
- **Input validation** and sanitization
- **Secure ignore list loading** (no more `exec()` calls)

**⚠️ Using the legacy toolchain (WiGLE credentials, GUI, batch analysis)? Run
`python3 legacy/migrate_credentials.py` before first use to secure your API keys.**
The headless EDC platform (`cyt_platform`) does not use WiGLE API keys.

## Features

- **Real-time Wi-Fi monitoring** with Kismet integration
- **Advanced surveillance detection** with persistence scoring
- **🆕 Automatic GPS integration** - extracts coordinates from Bluetooth GPS via Kismet
- **GPS correlation** and location clustering (100m threshold)
- **Spectacular KML visualization** for Google Earth with professional styling and interactive content
- **Multi-format reporting** - Markdown, HTML (with pandoc), and KML outputs
- **Time-window tracking** (5, 10, 15, 20 minute windows)
- **WiGLE API integration** for SSID geolocation
- **Multi-location tracking algorithms** for detecting following behavior
- **Enhanced GUI interface** with surveillance analysis button
- **Organized file structure** with dedicated output directories
- **Comprehensive logging** and analysis tools

## Requirements

- Python 3.9+ (CI tests 3.9 and 3.13)
- Kismet wireless packet capture
- Wi-Fi adapter supporting monitor mode
- Linux-based system
- WiGLE API key (optional)

## Installation & Setup

### 1. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Security Setup (legacy toolchain — REQUIRED FIRST TIME)
```bash
# Migrate credentials from insecure config.json (legacy toolchain only)
python3 legacy/migrate_credentials.py

# Verify security hardening
python3 legacy/chasing_your_tail.py
# Should show: "🔒 SECURE MODE: All SQL injection vulnerabilities have been eliminated!"
```

### 3. Configure System
Legacy tools read `config.json`; the headless EDC platform reads
`config.edc.json`. Edit the one matching your path — the legacy keys:
- Kismet database path pattern
- Log and ignore list directories
- Time window configurations
- Geographic search boundaries

## Usage

### Headless EDC analyzer (recommended)
```bash
# Install (venv)
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# Self-check (config + store + kismet glob)
python -m cyt_platform --self-check

# Run headless service (writes data/cyt.db + data/run/status.json)
python -m cyt_platform

# Legacy in-memory-only loop (no durable store)
python -m cyt_platform --legacy-loop
# or: python3 legacy/chasing_your_tail.py --legacy-loop
```

Status glance file: `data/run/status.json` → `state`: `clear` | `watch` | `alert` | `degraded` | `fail`.

### Operator CLI (cyt)

Every command below works as `cyt <cmd>` (console script) or
`python -m cyt_platform <cmd>` — they are the same entry point.

```bash
# One-glance status: state, open phenomenon incidents, components (add --json for machine output)
cyt status

# Per-check environment report: config, store schema v4, kismet captures,
# status publish path, LED path, detector registration (PASS/WARN/FAIL)
cyt doctor

# Validate the config file: invalid values print key + reason + acceptable range
cyt config check

# Inspect and disposition incidents (the state machine rejects illegal moves with exit 2)
cyt incident show <key>
cyt incident dismiss <key> --reason "my own router"   # false_positive
cyt incident confirm <key> --reason "my device"       # known_device
cyt incident resolve <key> --reason "handing off"     # resolved (needs a progressed incident)
cyt incident reopen <key> --reason "still seeing it"  # terminal states only

# Deterministic replay of a labeled scenario; `cyt eval` runs the full corpus
# against eval/gates.json (exit 0 pass, 1 gate failure, 2 harness/gates error)
cyt replay --session scenarios/replay/commute-quiet.json
cyt eval

# Export persisted observations as a replayable scenario document (B6):
# replay the export with `cyt replay --session <out>` and compare the
# incidents against the live run. Alert and BLE detection data survive the
# export; probe-SSID text was never recorded, and detections that depend on
# operator config (trusted APs, protected MACs) must be re-supplied via
# config_overrides on the exported document.
cyt export --out /tmp/session.json --since 1779000000 --until 1779086400
```

### P1 Trust (encryption, baseline, LED, wipe)
```bash
# Store encryption key
python -m cyt_platform --init-store-key data/store.key
# Enable store.encryption in config (see config.edc.json)

# Baseline (home/work filtering)
python -m cyt_platform baseline list
python -m cyt_platform baseline mark --place home --key AA:BB:CC:DD:EE:FF --false

# LED consumer (writes data/run/led.state)
python -m cyt_platform --led-once

# Panic wipe (destructive)
python -m cyt_platform --panic-wipe --confirm YES
```

### P2 Payoff (debrief, push, GPS co-travel)
```bash
# End-of-day narrative (writes logs/debrief_YYYY-MM-DD.md)
python -m cyt_platform --debrief
python -m cyt_platform --debrief 2026-08-05

# Push queue (ntfy) — enable push in config, then:
python -m cyt_platform --push-flush
# Live analyzer also enqueues on alert/fail transitions and flushes each cycle
```

### P3 RF expansion (IE fingerprint, BLE, deauth, rogue AP)
Enabled by default in service loop when Kismet DB is present:
- **IE fingerprinting** — re-links randomized MACs via probe SSID set + IE tags
- **BLE tracker heuristics** — AirTag/Tile-style devices → incidents
- **Deauth detector** — `cyt_platform/deauth_detector.py` (CM5 branch)
- **Rogue/evil-twin** — `cyt_platform/rogue_ap_detector.py` (CM5 branch)
- **GPS co-travel** — multi-cluster persistence scoring

Configure `rf`, `ie_fingerprint`, `ble_tracker`, `gps_fusion`, `deauth_detection`, `rogue_ap_detection` in config.

Field deploy: see `deploy/FIELD_DEPLOY.md` and `docs/EDC_PLATFORM_DESIGN.md`.

### GUI Interface (lab / optional — quarantined)
```bash
python3 legacy/cyt_gui.py  # Enhanced GUI with surveillance analysis
```
**GUI Features:**
- 🗺️ **Surveillance Analysis** button - GPS-correlated persistence detection with spectacular KML visualization
- 📈 **Analyze Logs** button - Historical probe request analysis
- Real-time status monitoring and file generation notifications

### Command Line Monitoring
```bash
# Start headless EDC analyzer (preferred)
python -m cyt_platform

# Start Kismet (ONLY working script - July 23, 2025 fix)
./legacy/start_kismet_clean.sh
```

### Data Analysis (quarantined)
```bash
# Analyze collected probe data (past 14 days, local only - default)
python3 legacy/probe_analyzer.py

# Analyze past 7 days only
python3 legacy/probe_analyzer.py --days 7

# Analyze ALL logs (may be slow for large datasets)
python3 legacy/probe_analyzer.py --all-logs

# Analyze WITH WiGLE API calls (consumes API credits!)
python3 legacy/probe_analyzer.py --wigle
```

### Surveillance Detection & Advanced Visualization (quarantined)
```bash
# 🆕 NEW: Automatic GPS extraction with spectacular KML visualization
python3 legacy/surveillance_analyzer.py

# Run analysis with demo GPS data (for testing - uses Phoenix coordinates)
python3 legacy/surveillance_analyzer.py --demo

# Analyze specific Kismet database
python3 legacy/surveillance_analyzer.py --kismet-db /path/to/kismet.db

# Focus on stalking detection with a high threat threshold
python3 legacy/surveillance_analyzer.py --stalking-only --min-threat 0.8

# Export results to JSON for further analysis
python3 legacy/surveillance_analyzer.py --output-json analysis_results.json

# Analyze with external GPS data from JSON file
python3 legacy/surveillance_analyzer.py --gps-file gps_coordinates.json
```

### Ignore List Management (quarantined)
```bash
# Create new ignore lists from current Kismet data
python3 legacy/create_ignore_list.py
```
**Note**: Ignore lists are stored as JSON files in `./ignore_lists/`

## Core Components

**Canonical platform** — `cyt_platform/` (the headless EDC service; use the
Operator CLI above; design in `docs/EDC_PLATFORM_DESIGN.md`):

- **cyt_platform/secure_database.py**: SQL injection prevention, read-only capture access
- **cyt_platform/secure_credentials.py**: Encrypted credential management
- **cyt_platform/secure_ignore_loader.py**: Safe ignore list loading
- **cyt_platform/secure_main_logic.py**: Secure monitoring logic (window matching + hooks)
- **cyt_platform/input_validation.py**: Input sanitization and validation
- **cyt_platform/deauth_detector.py** / **rogue_ap_detector.py**: CM5-branch RF detectors

**Quarantined legacy tools** — `legacy/` (archived; map in `legacy/README.md`):

- **legacy/chasing_your_tail.py**: Historical entry point → dispatches to `cyt_platform`
- **legacy/cyt_gui.py**: Enhanced Tkinter GUI with surveillance analysis capabilities
- **legacy/surveillance_analyzer.py**: GPS surveillance detection with automatic coordinate extraction and advanced KML visualization
- **legacy/surveillance_detector.py**: Core persistence detection engine for suspicious device patterns
- **legacy/gps_tracker.py**: GPS tracking with location clustering and spectacular Google Earth KML generation
- **legacy/probe_analyzer.py**: Post-processing tool with WiGLE integration
- **legacy/migrate_credentials.py**: Credential migration tool (legacy toolchain)
- **legacy/start_kismet_clean.sh**: ONLY working Kismet startup script (July 23, 2025 fix)

## Legacy Quarantine

The repository root once carried two generations of tooling. Per locked
decision 2 of the trustworthiness build, `cyt_platform/` is the canonical
platform: shared modules with a proven runtime role moved **into** the
package, and every historical root-level tool moved under `legacy/` with a
README mapping each tool to its canonical successor (`legacy/README.md`).
Nothing under `cyt_platform/` imports from `legacy/` — enforced by
`tests/test_legacy_quarantine.py`.

## Output Files & Project Structure

### Organized Output Directories
- **Surveillance Reports**: `./surveillance_reports/surveillance_report_YYYYMMDD_HHMMSS.md` (markdown)
- **HTML Reports**: `./surveillance_reports/surveillance_report_YYYYMMDD_HHMMSS.html` (styled HTML with pandoc)
- **KML Visualizations**: `./kml_files/surveillance_analysis_YYYYMMDD_HHMMSS.kml` (spectacular Google Earth files)
- **CYT Logs**: `./logs/cyt_log_MMDDYY_HHMMSS`
- **Analysis Logs**: `./analysis_logs/surveillance_analysis.log`
- **Probe Reports**: `./reports/probe_analysis_report_YYYYMMDD_HHMMSS.txt`

### Configuration & Data
- **Ignore Lists**: `./ignore_lists/mac_list.json`, `./ignore_lists/ssid_list.json`
- **Encrypted Credentials**: `./secure_credentials/encrypted_credentials.json`

## Technical Architecture

### Time Window System
Maintains four overlapping time windows to detect device persistence:
- Recent: Past 5 minutes
- Medium: 5-10 minutes ago
- Old: 10-15 minutes ago
- Oldest: 15-20 minutes ago

### Surveillance Detection
Advanced persistence detection algorithms analyze device behavior patterns:
- **Temporal Persistence**: Consistent device appearances over time
- **Location Correlation**: Devices following across multiple locations
- **Probe Pattern Analysis**: Suspicious SSID probe requests
- **Timing Analysis**: Unusual appearance patterns
- **Persistence Scoring**: Weighted scores (0-1.0) based on combined indicators
- **Multi-location Tracking**: Specialized algorithms for detecting following behavior

### GPS Integration & Spectacular KML Visualization (Enhanced!)
- **🆕 Automatic GPS extraction** from Kismet database (Bluetooth GPS support)
- **Location clustering** with 100m threshold for grouping nearby coordinates
- **Session management** with timeout handling for location transitions
- **Device-to-location correlation** links Wi-Fi devices to GPS positions
- **Professional KML generation** with spectacular Google Earth visualizations featuring:
  - Color-coded persistence level markers (green/yellow/red)
  - Device tracking paths showing movement correlation
  - Rich interactive balloon content with detailed device intelligence
  - Activity heatmaps and surveillance intensity zones
  - Temporal analysis overlays for time-based pattern detection
- **Multi-location tracking** detects devices following across locations with visual tracking paths

## Configuration

Legacy-toolchain settings are centralized in `config.json`:
```json
{
  "kismet_db_path": "/path/to/kismet/*.kismet",
  "log_directory": "./logs/",
  "ignore_lists_directory": "./ignore_lists/",
  "time_windows": {
    "recent": 5,
    "medium": 10,
    "old": 15,
    "oldest": 20
  }
}
```

WiGLE API credentials are now securely encrypted in `secure_credentials/encrypted_credentials.json` (the manager lives at `cyt_platform/secure_credentials.py` since the quarantine).

## Security Features

- **Parameterized SQL queries** prevent injection attacks
- **Encrypted credential storage** protects API keys
- **Input validation** prevents malicious input
- **Audit logging** tracks all security events
- **Safe ignore list loading** eliminates code execution risks

## Author

@matt0177

## License

MIT License

## Disclaimer

This tool is intended for legitimate security research, network administration, and personal safety purposes. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.