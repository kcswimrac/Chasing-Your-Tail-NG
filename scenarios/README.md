# Eval scenario corpus (D7)

Labeled replay scenarios plus the calibrated gates that turn them into the
merge gate. `python -m cyt_platform eval --scenarios scenarios/replay
--gates eval/gates.json` exits non-zero on any regression.

## Layout

- `*.json` — 32 scenarios: **10 normal** (`expect.detect=false`),
  **18 suspicious** (`expect.detect=true` with `max_latency_cycles`),
  **4 edge** (GPS dropout, clock jump, corrupt rows, detector failure —
  labeled `expect.detect=false` with a state assertion).
- `../eval/gates.json` — calibrated thresholds, evaluated by
  `cyt_platform/replay/evaluation.py`.
- `generate_corpus.py` — regenerates the 25 generated scenarios
  byte-identically (`python3 scenarios/generate_corpus.py [output-dir]`).

Seven hand-authored fixtures from the replay-engine PRs (cafe-evil-twin,
commute-deauth-burst, commute-quiet, cotravel-deauth-merge, detector_failure,
walk-ble-tracker, walk-cotravel) are originals, not generator output; they are
edited by hand. Every other file regenerates byte-for-byte — a generator
change that shifts content shifts a committed fixture and shows up as a diff.

## Labels

```json
"labels": {
  "kind": "normal | suspicious | edge",
  "expect": {
    "detect": true,
    "state": "watch | alert | clear | degraded | fail",
    "max_latency_cycles": 2,
    "max_incidents": 1,
    "entity_keys": ["AA:BB:CC:00:00:01"]
  }
}
```

`max_latency_cycles` bounds the cycle at which detection is allowed to appear
— it catches silent misses (never detected) and latency regressions (detected
too late) in one number. `entity_keys` is the SET of incident subjects the
scenario may file; normal/edge scenarios typically omit it and assert
`detect=false`. Labels are validated up front (`validate_labels`): a normal
scenario cannot label `detect=true`, a detect=true scenario must carry a
latency budget, and every scenario needs >= 2 cycles so restart injection has
somewhere to fire.

## What the gates enforce

| Gate | Meaning |
| --- | --- |
| `false_alert_scenarios` / `false_incident_scenarios` | Zero false alerts and incidents on the normal/edge corpus — repeated observation alone never alerts |
| `missed_scenarios` / `latency_breaches` | Every suspicious scenario detects within its labeled latency — no silent misses |
| `state_mismatch_scenarios` / `entity_mismatch_scenarios` / `excess_incident_scenarios` | Final state, subject set, and incident count match the labels (one phenomenon = one incident) |
| `determinism_breaches` | A second engine run reproduces the first byte-for-byte |
| `restart_breaches` | A mid-scenario restart from the persisted cursor reaches the same incidents and event stream |
| `raw_render_breaches` | Adversarial markup in display fields reaches renderers inert |
| `corpus_min_scenarios` | The corpus never shrinks below 25 scenarios |

Thresholds live in `eval/gates.json` (`gate_version` guards against stale
gate documents).

## Calibration contract

`eval/gates.json` was calibrated from this corpus's initial run: thresholds
were set to the observed behavior (the only non-zero knob is
`worst_latency_cycles: 2`; every correctness gate is locked at zero), and the
first CI run of the corpus job was green. Two rules keep calibration honest:

1. **Thresholds calibrate away variance; they never hide regressions.** A red
   eval on an untouched corpus is a product-behavior change to review, not a
   gate to loosen. Loosening a gate requires a corpus change or a deliberate
   decision recorded in the PR that bumps `gate_version`.
2. **A calibration run that reveals a detection gap is a bug report**, not a
   relabeling exercise: a suspicious scenario that fails to detect, or a
   normal one that alerts, gets fixed in the detectors — or the scenario is
   explicitly redesigned with the product reason documented.

## Restart-equivalence churn note

The deauth detector accumulates events in memory and re-observes its open
attack each cycle; a service restart starts from a cold event list (persisted
watermarks keep processed history from replaying), so `last_seen` and
`observation_count` on an ongoing attack can lag after a restart until the
attack rate rebuilds. The restart-equivalence comparison tolerates exactly
that churn and nothing else: incident keys, `first_seen`, status, severity,
entity, and the full event stream must match a single-pass run.
