## What TripleGeo Does

- Captures the best available GPS location using a fallback chain:
  `current gpsd -> cached GPS -> AP cache`
- Correlates handshake events with cached AP metadata
- Writes optional coordinate sidecar files next to handshake captures
- Sends Discord webhook notifications for handshakes
- Exports AP data in WiGLE-friendly formats
- Optionally uploads AP data to WiGLE on a timed schedule
- Looks up vendors from an IEEE OUI database

## Requirements

- Pwnagotchi plugin environment
- `gpsd` and Python `gps` module if you want live GPS
- Python `requests` module for Discord and WiGLE uploads
- An OUI database file if you want vendor lookups

## Installation

Place the v2 plugin file in your Pwnagotchi plugins directory as `triplegeo.py`, then enable it in `config.toml`.

## Minimal Config Example

```toml
main.plugins.triplegeo.enabled = true
main.plugins.triplegeo.discord_webhook_url = "https://discord.com/api/webhooks/..."
main.plugins.triplegeo.use_last_gps = true
main.plugins.triplegeo.debug_logging = true
```

## Full Supported Config

These are the options the current v2 plugin actually reads and uses.

```toml
main.plugins.triplegeo.enabled = false
main.plugins.triplegeo.mode = ["gps", "google", "wigle"]

main.plugins.triplegeo.google_api_key = ""

main.plugins.triplegeo.wigle_user = ""
main.plugins.triplegeo.wigle_token = ""
main.plugins.triplegeo.wigle_upload = false
main.plugins.triplegeo.wigle_delay = 300
main.plugins.triplegeo.max_wigle_per_minute = 10
main.plugins.triplegeo.wigle_api_base = "https://api.wigle.net/api/v3"
main.plugins.triplegeo.wigle_export_dir = "/root/triplegeo_wigle_exports"
main.plugins.triplegeo.wigle_format = "kismet_csv"

main.plugins.triplegeo.handshake_dir = "/home/pi/handshakes"
main.plugins.triplegeo.processed_file = "/root/.triplegeo_processed"
main.plugins.triplegeo.pending_file = "/root/.triplegeo_pending"
main.plugins.triplegeo.global_log_file = "/root/triplegeo_globalaplog.jsonl"

main.plugins.triplegeo.discord_webhook_url = ""

main.plugins.triplegeo.oui_db_path = "/usr/local/share/pwnagotchi/ieee_oui.txt"

main.plugins.triplegeo.cache_expire_minutes = 60
main.plugins.triplegeo.debug_logging = true

main.plugins.triplegeo.gps_cache_file = "/root/.triplegeo_gps_cache"
main.plugins.triplegeo.use_last_gps = true
main.plugins.triplegeo.gps_cache_expiry_hours = 24
main.plugins.triplegeo.gps_accuracy_threshold = 100
main.plugins.triplegeo.fallback_to_cached_gps = true
```

## Option Reference

### Core

- `enabled`
  Enables the plugin.
- `mode`
  Stored in config and defaults to `["gps", "google", "wigle"]`. The current code does not actively branch on this value.
- `debug_logging`
  Enables extra logging.

### Handshake and State Files

- `handshake_dir`
  Default handshake directory.
- `processed_file`
  JSON file storing processed handshakes.
- `pending_file`
  JSON file storing pending handshake entries.
- `global_log_file`
  Reserved path for global AP logging.

### GPS

- `use_last_gps`
  Reuse the last known valid GPS reading if current GPS is unavailable.
- `gps_cache_file`
  File used to persist cached GPS coordinates.
- `gps_cache_expiry_hours`
  How long cached GPS remains valid.
- `gps_accuracy_threshold`
  Maximum acceptable GPS horizontal accuracy in meters for fresh readings.
- `fallback_to_cached_gps`
  Allows GPS fallback from cached AP location data.

### AP Cache

- `cache_expire_minutes`
  How long AP metadata stays in memory before cleanup.

### Discord

- `discord_webhook_url`
  HTTPS webhook used for handshake notifications. If set, the plugin can auto-enable itself on load.

### WiGLE

- `wigle_upload`
  Enables WiGLE upload support.
- `wigle_user`
  WiGLE API username.
- `wigle_token`
  WiGLE API token.
- `wigle_delay`
  Minimum time between upload attempts, in seconds.
- `max_wigle_per_minute`
  Present in config defaults, but not currently enforced by the uploader logic.
- `wigle_api_base`
  WiGLE API base URL.
- `wigle_export_dir`
  Directory where compressed export files are written.
- `wigle_format`
  Export format: `kismet_csv`, `netxml`, or `custom_csv`.

### Vendor Lookup

- `oui_db_path`
  Path to the IEEE OUI text database used for vendor lookups.

### Google

- `google_api_key`
  Present in config defaults, but not currently used by the current v2 code path.

## WiGLE Export Formats

- `kismet_csv`
  Default and recommended for WiGLE uploads
- `netxml`
  XML export
- `custom_csv`
  Simplified CSV export

## Environment Variables

TripleGeo can also read secrets from environment variables with the `TRIPLEGEO_` prefix.

Examples:

```bash
TRIPLEGEO_DISCORD_WEBHOOK_URL
TRIPLEGEO_WIGLE_USER
TRIPLEGEO_WIGLE_TOKEN
TRIPLEGEO_ENABLED
```

## Files Created by the Plugin

- `processed_file`
  Processed handshake state
- `pending_file`
  Pending handshake state
- `gps_cache_file`
  Cached GPS coordinates
- `/root/.triplegeo_wigle_state.json`
  WiGLE upload state
- `*.triplegeo.coord.json`
  Coordinate sidecar written next to a handshake file when GPS is available
- `wigle_export_dir/triplegeo_export_*.gz`
  Exported WiGLE files



======================================================================================================================================================================================



net_pos.py is based upon the original plugin, but it works. Use Google Geolocation API.





main.plugins.net-pos.enabled = true

main.plugins.net-pos.api_key = "GOOGLE API KEY HERE"

main.plugins.net-pos.loc_file = "/home/pi/.pwn/locations.json"

main.plugins.net-pos.update_interval = 300





======================================================================================================================================================================================



ble_wardrive.py will scan on its own loop, below is an interval you can set. It will report what it sees via ntfy notifications, including RSSI, name, latitude, longitude, altitude (from GPS or Google API), device fingerprinting/classification, mesh network detection, vulnerability detection (static MAC, weak names, services), anomaly detection (intervals and abnormal data), and rogue device detection. This uses IEEE OUI.txt for OUI lookup and Bluetooth Company ID database for manufacturer identification.



This does not interfere with any bluetooth tether. Note: This script in its current state does not invoke the WiFi - Google Geolocation API is incomplete, however it functions via GPSD with a GPS dongle. Please ensure in config.toml that bettercap.silence = [] does not include ble.device.new or ble.device.lost.



sudo wget https://standards-oui.ieee.org/oui/oui.txt -O /usr/local/share/pwnagotchi/ieee_oui.txt



sudo wget -O /usr/local/share/pwnagotchi/bluetooth_company_ids.json https://raw.githubusercontent.com/NordicSemiconductor/bluetooth-numbers-database/master/v1/company_identifiers.json



Configuration for ble_wardrive.py:



main.plugins.ble_wardrive.enabled = true

main.plugins.ble_wardrive.ntfy_server = "http://localhost:8080"

main.plugins.ble_wardrive.ntfy_topic = "ble_wardrive"

main.plugins.ble_wardrive.scan_interval = 10

main.plugins.ble_wardrive.scan_duration = 5

main.plugins.ble_wardrive.use_gpsd = true

main.plugins.ble_wardrive.google_api_key = "GOOGLE API KEY"

main.plugins.ble_wardrive.oui_db_path = "/usr/local/share/pwnagotchi/ieee_oui.txt"

main.plugins.ble_wardrive.bluetooth_company_db_path = "/usr/local/share/pwnagotchi/bluetooth_company_ids.json"

main.plugins.ble_wardrive.auto_download_databases = true



Ntfy notifications will log connection errors to the pwnagotchi log if bluetooth tether is unavailable, making it easy to diagnose connectivity issues.



If you are running into issues with your bluetooth tether not reconnecting upon boot (since triplegeo.py and my other ones call for bluetooth/internet connect)
sudo apt update

sudo apt install bluez bluez-tools

sudo nano /etc/systemd/system/bluetooth.service.d/override.conf

[Service]

ExecStart=

ExecStart=/usr/libexec/bluetooth/bluetoothd --experimental



sudo crontab -e (add this at the end)

@reboot /usr/bin/bt-network -c INSERT:YOUR:PHONE:MAC nap &

@reboot sleep 5 && /sbin/ip link set bnep0 up

@reboot sleep 6 && /sbin/ip addr add 192.168.44.44/24 dev bnep0

@reboot sleep 7 && /sbin/ip route replace default via 192.168.44.1 dev bnep0 metric 100
