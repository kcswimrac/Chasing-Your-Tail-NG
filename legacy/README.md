# Legacy tools (quarantined)

Locked decision 2 of the trustworthiness build ends the two-generation
ambiguity of this repository: **`cyt_platform/` is the canonical platform** —
the headless EDC service (`cyt` / `python -m cyt_platform`) — and the
historical root-level script generation lives here, preserved but no longer
silently presented as production paths. Every file below was moved out of the
repository root with `git mv` (history intact); nothing was deleted.

## What is canonical

- **`cyt_platform/`** — the platform: store (schema v4), service loop,
  detectors, confidence fusion, incident lifecycle, replay/eval harness,
  operator CLI (`cyt status | doctor | config check | incident | replay | eval`).
- Shared modules with a **proven runtime role** moved *into* the package
  during the quarantine (they are imported by `cyt_platform` at runtime, and
  the import guard forbids the platform from depending on this directory):
  `input_validation.py`, `secure_database.py`, `secure_ignore_loader.py`,
  `secure_main_logic.py`, `secure_credentials.py`, `deauth_detector.py`,
  `rogue_ap_detector.py`, and `legacy_loop.py` (the `--legacy-loop`
  in-memory loop, historically the body of `chasing_your_tail.py`).

## Map: legacy tool → canonical successor

| Legacy tool (here) | Canonical successor | What happened |
| --- | --- | --- |
| Window matching core (`secure_main_logic.py` + `secure_database.py`) | `cyt_platform/secure_main_logic.py`, `cyt_platform/secure_database.py` | Retained (runtime role), re-contracted: window sets persist and rehydrate across restarts (`cyt_platform/windows.py`, PR #9) and `on_match` events fuse into incidents via `cyt_platform/monitor_adapter.py` instead of dying in a log file. |
| In-memory monitor loop (`chasing_your_tail.py`) | `cyt_platform/legacy_loop.py` + the `chasing_your_tail.py` shim here | The loop moved into the package as the platform's `--legacy-loop` compat path; the shim here keeps the historical command working and dispatches to the platform by default. |
| Deauth / rogue-AP detection (`deauth_detector.py`, `rogue_ap_detector.py`) | `cyt_platform/deauth_detector.py`, `cyt_platform/rogue_ap_detector.py` | Migrated to the `DetectionResult` + `EvidenceLine` contracts (PR #11) with watermark persistence (PR #4), then moved into the package. No archived copy remains. |
| GPS "independent locations" clustering (`gps_tracker.py`) | `cyt_platform/location.py` | Re-implemented as haversine-radius clustering, distinct-visit splitting, and travel-feasibility checks (PR #6); the grid-cell counting that made 10 m apart count as two locations is not carried over. |
| Surveillance persistence scoring (`surveillance_detector.py`) | platform detection → fusion → incident pipeline (`cyt_platform/detectors.py`, `confidence.py`, `incidents.py`) | Re-implemented on the evidence-first contracts (PRs #11–#13); the archived batch tool stays for offline "what would it have said" comparisons. |
| BLE tracker heuristic | `cyt_platform/ble_tracker.py` | Re-implemented with temporal evidence in the platform detector layer. |
| Credential management (`secure_credentials.py`) | `cyt_platform/secure_credentials.py` | Canonicalized (test-mode fixes landed in PR #3); the runtime `secure_credentials/` key store stays at the repository root. |
| Ignore-list loading (`secure_ignore_loader.py`) | `cyt_platform/secure_ignore_loader.py` | Canonicalized; paths come from platform config (`cyt_platform/config.py`). |

Plainly archived here — no platform successor needed (lab UIs, batch
post-processing, demo scripts, and crontab-era boot helpers):

- `cyt_gui.py` — Tkinter lab GUI (spawns the quarantined tools by path)
- `surveillance_analyzer.py`, `surveillance_detector.py`, `gps_tracker.py` — batch analysis stack (render escaping kept from PR #3; guard-tracked in `tests/test_render_escaping.py`)
- `probe_analyzer.py` — WiGLE post-processing
- `create_ignore_list.py`, `ignore_list.py`, `ignore_list_ssid.py` — ignore-list tooling and the pre-JSON `exec()`-era data lists
- `blackhat_demo.py` — demo driver
- `migrate_credentials.py` — legacy-toolchain credential migration
- `monitor.sh`, `start_gui.sh`, `start_kismet_clean.sh` — crontab-era helpers (platform deployments use `deploy/systemd/`)
- `chasing_your_tail.py` — compat shim (see the map above)

## Import rule (enforced)

`legacy/` may import `cyt_platform/` (the archived tools consume the
canonical security modules). The reverse is forbidden: **no module under
`cyt_platform/` may import anything quarantined here** — enforced by
`tests/test_legacy_quarantine.py`, which derives the quarantined-module set
from this directory's contents, so quarantining a new module auto-arms the
guard. Scripts that import platform modules bootstrap the repository root
onto `sys.path`, so they run from a bare source checkout; installing the
project (`pip install -e ".[dev]"`) also satisfies them.

## Test status

**All quarantined-path tests are green — there are no expected-failure
marks.** The archived tools are importable under their historical top-level
names via the pytest path entry (`pyproject.toml` →
`pythonpath = [".", "legacy"]`), so the suites that exercise them
(`test_render_escaping.py`, `test_credential_migration.py`,
`test_regression_baseline.py`, …) run unmodified in behavior. Locked
decision 9's alternative branch (explicit expected-failure marks) is
unused and intentionally not invoked.

## Configuration

`config.json` (repository root) is the legacy-toolchain config. The
platform reads `config.edc.json`. The legacy loop spawned by
`cyt_platform --legacy-loop` resolves `config.json` relative to the
working directory, exactly as it always has.
