# CYT Field Deploy Checklist (EDC / CM5)

**Passive personal counter-surveillance only.** No active RF attacks.

## Before carrying in public

1. **Full-disk encryption** (LUKS) **or** fscrypt on `data_dir` — **required** until app-level store encryption (P1).
2. Create FDE acknowledgment so the analyzer stops warning:  
   `sudo mkdir -p /etc/cyt && sudo touch /etc/cyt/fde_ack`
3. Confirm store + logs permissions:
   - `/var/lib/cyt` → `0700` cyt:cyt  
   - `cyt.db` (+ WAL/SHM) → `0600`  
   - `/var/log/cyt` → `0700`  
   - `/run/cyt` → `0750` cyt:cyt  
   - `status.json` → `0640`
4. **`service.legacy_log_file: false`** in `/etc/cyt/config.json` (use `config.edc.json` as template).
5. **No WiGLE / master password** on the analyzer unit environment.
6. Operator acknowledgment: this device stores **third-party radio identifiers and timestamps** (and later locations). Local law applies. Seizure of the device is a privacy incident.

## Install sketch

```bash
sudo useradd -r -s /usr/sbin/nologin -G kismet cyt || true
sudo mkdir -p /opt/cyt /var/lib/cyt /var/log/cyt /etc/cyt
sudo cp -a . /opt/cyt/
cd /opt/cyt
python3 -m venv .venv
.venv/bin/pip install -e .
sudo cp config.edc.json /etc/cyt/config.json
sudo chown -R cyt:cyt /var/lib/cyt /var/log/cyt
sudo cp deploy/systemd/*.service deploy/systemd/*.target /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cyt.target
```

## Health

```bash
systemctl status cyt-analyzer
cat /run/cyt/status.json
python -m cyt_platform --self-check -c /etc/cyt/config.json
```

## Status LED mapping (consumer)

| state | LED |
|-------|-----|
| clear | green |
| watch | amber |
| alert | red blink |
| fail  | red solid |

`status.json` carries no raw MAC, SSID, or device-name text. Identity is
redacted at the detector source: MACs render as `AA:BB:xx:xx:xx:FF`
(OUI + last octet), SSIDs and device names as stable
`ssid(len=N,h=XXXX)` tokens; evidence is counts + component health plus
those redacted reason lines.

## Encryption + panic wipe (P1)

```bash
# Generate store key (once)
sudo python -m cyt_platform --init-store-key /etc/cyt/store.key
sudo chown root:cyt /etc/cyt/store.key && sudo chmod 0640 /etc/cyt/store.key
# config.edc.json already has store.encryption.enabled=true and key_file path

# Panic wipe (device lost / seize risk)
python -m cyt_platform --panic-wipe --confirm YES -c /etc/cyt/config.json
```

Retention: 14 days events/closed incidents; 7 days heartbeats; 30 days entities.

## Baseline learning

```bash
# While at home (manual place override in config):
#   "baseline": { "enabled": true, "current_place": "home", ... }

# Mark neighbor as normal / false positive
python -m cyt_platform baseline mark --place home --key AA:BB:CC:DD:EE:FF
python -m cyt_platform baseline mark --place home --key AA:BB:CC:DD:EE:FF --false
python -m cyt_platform baseline list
```

## LED glance consumer

```bash
python -m cyt_platform --led          # continuous
python -m cyt_platform --led-once     # single write to /run/cyt/led.state
# Maps: clear→green, watch→amber, alert→red_blink, fail→red_solid
```
