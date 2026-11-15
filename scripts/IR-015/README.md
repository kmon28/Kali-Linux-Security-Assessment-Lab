# IR-015 — User-level systemd persistence detector

**Status:** New portfolio reference implementation, based on the documented IR-015 detection design. These are **not** recovered byte-for-byte copies of the original scripts from the Kali VM, and they were **not** the source files used to produce the historical screenshots.

## What the scripts do

- `user_service_detector.py`: **read-only** inventory of user-level systemd service units under `~/.config/systemd/user`. Flags an enabled startup link (+2) and an `ExecStart` containing `/home/` or `/tmp/` (+2). Maximum **4/4**. This is an explainable lab heuristic, **not** a probability of malware.
- `export_alerts.py`: Saves a fresh JSON snapshot of the current detector results, with a UTC collection timestamp.
- `validate_alerts.py`: Validates JSON structure and optionally compares service scores with explicitly supplied expected values.
- `agent.sh`: A harmless optional simulation that only appends timestamps to a local log. It does **not** establish persistence by itself.

## Requirements

Python 3.9+ on Linux, standard library only. No root privileges needed for the detector. The default scan is read-only.

## Run

```bash
python3 scripts/IR-015/user_service_detector.py
python3 scripts/IR-015/user_service_detector.py --json
python3 scripts/IR-015/export_alerts.py --output /tmp/ir015-current-alerts.json
python3 scripts/IR-015/validate_alerts.py /tmp/ir015-current-alerts.json
```

Use `--config-root /path/to/test-config` with the detector or exporter to inspect an isolated test fixture instead of your live user configuration.

## Detection caveats

- The heuristic can flag legitimate home-directory scripts; review service purpose and ownership.
- It does not detect system-wide units, transient units, systemd generators, cron, timers, malicious binaries, or all alternate enablement methods.
- A `0/4` score is **not** a clean-host guarantee.
- It scans configuration at a point in time, not process execution or historical journal events.
- Symlinks are interpreted as startup configuration indicators, not proof that a service ran.
- Original IR-015 screenshots and historical findings remain in the [incident report](../../reports/IR-015-Linux-User-Systemd-Persistence-Investigation.md).

## Safety

Run only in your authorized lab. Do not enable the sample agent as a service on a production host. It has no stop condition other than process termination, and its log grows until stopped.
