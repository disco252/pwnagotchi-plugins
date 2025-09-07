import logging
import requests
import os
import json
import base64
import time
import threading
import pwnagotchi.plugins as plugins

try:
    import gps
    HAS_GPSD = True
except ImportError:
    HAS_GPSD = False

# OUI lookup helper (simple cache-based, update with your own list if desired)
def oui_lookup(mac):
    # Example: Just grabs the first three bytes of MAC for simple OUI mapping
    vendors = {
        "00:11:22": "VendorA Inc.",
        "AA:BB:CC": "VendorB Corp.",
        # Add more prefixes as needed or load from deps/ieee-oui.json
    }
    prefix = mac.upper()[:8]
    return vendors.get(prefix, "Unknown")

class TripleGeo(plugins.Plugin):
    __author__ = "disco252 & community"
    __version__ = "1.5"
    __license__ = "GPL3"
    __description__ = (
        "Advanced geolocation, AP/client mapping, and Discord notifications for Pwnagotchi. "
        "Uses GPS, Google, or WiGLE; posts detailed events to Discord."
    )
    __name__ = "triplegeo"
    __defaults__ = {
        "enabled": False,
        "google_api_key": "",
        "wigle_user": "",
        "wigle_token": "",
        "handshake_dir": "/home/pi/handshakes",
        "processed_file": "/root/.triplegeo_processed",
        "pending_file": "/root/.triplegeo_pending",
        "wigle_delay": 2,
        "max_wigle_per_minute": 10,
        "wigle_upload": True,
        "gpsd_host": "localhost",
        "gpsd_port": 2947,
        "global_log_file": "/root/triplegeo_globalaplog.jsonl",
        "discord_webhook_url": "", # Add this to your config.toml!
    }
    GOOGLE_API_URL = "https://www.googleapis.com/geolocation/v1/geolocate?key={api}"
    WIGLE_API_URL = "https://api.wigle.net/api/v2/network/search"
    WIGLE_UPLOAD_URL = "https://api.wigle.net/api/v2/network/upload"

    def __init__(self):
        super().__init__()
        if not hasattr(self, 'options'):
            self.options = dict(self.__defaults__)
        self.api_mutex = threading.Lock()
        self.processed = set()
        self.pending = []
        self.gps_session = None
        self._gps_last = None
        self._global_ap_log = set()
        self._load_storage()
        self.connect_gpsd()

    def _load_storage(self):
        try:
            if os.path.exists(self.options["processed_file"]):
                with open(self.options["processed_file"], "r") as f:
                    self.processed = set(json.load(f))
        except Exception as e:
            logging.warning(f"[TripleGeo] Unable to load processed file list: {e}")
        try:
            if os.path.exists(self.options["pending_file"]):
                with open(self.options["pending_file"], "r") as f:
                    self.pending = json.load(f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Unable to load pending uploads: {e}")

    def connect_gpsd(self):
        if not HAS_GPSD:
            self.gps_session = None
            logging.warning("[TripleGeo] gpsd-py3 module not found; GPS disabled.")
            return
        try:
            self.gps_session = gps.gps(self.options["gpsd_host"], self.options["gpsd_port"], mode=gps.WATCH_ENABLE)
            logging.info("[TripleGeo] Connected to gpsd for GPS.")
        except Exception as e:
            self.gps_session = None
            logging.warning(f"[TripleGeo] Could not connect to gpsd: {e}")

    def get_gps_coord(self, max_attempts=10):
        if not self.gps_session:
            return self._gps_last
        try:
            count = 0
            while count < max_attempts:
                report = self.gps_session.next()
                if report.get('class') == 'TPV' and getattr(report, 'mode', 1) >= 2:
                    if hasattr(report, 'lat') and hasattr(report, 'lon'):
                        self._gps_last = (float(report.lat), float(report.lon))
                        return self._gps_last
                count += 1
        except Exception as e:
            logging.warning(f"[TripleGeo] GPS exception: {e}")
        return self._gps_last

    def on_unfiltered_ap_list(self, agent, ap_list):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        now = time.time()
        for ap in ap_list:
            key = f"{ap.get('mac','')}|{ap.get('hostname','')}|{ap.get('client','')}"
            if key and key not in self._global_ap_log:
                entry = {
                    "timestamp": now,
                    "ssid": ap.get("hostname", "<unknown>"),
                    "bssid": ap.get("mac", ""),
                    "client": ap.get("client", ""),
                    "rssi": ap.get("rssi", "N/A"),
                    "channel": ap.get("channel", "N/A"),
                    "encryption": ap.get("encryption", "N/A"),
                    "lat": gps_coord[0] if gps_coord else "N/A",
                    "lon": gps_coord[1] if gps_coord else "N/A",
                    "source": "gpsd" if gps_coord else "none",
                    "vendor": oui_lookup(ap.get("mac", "")),
                    "google_maps": "https://www.google.com/maps/search/?api=1&query={},{}".format(gps_coord[0], gps_coord[1]) if gps_coord else "N/A",
                    "pwnagotchi_name": getattr(agent, "name", lambda: "Unknown")() if agent else "Unknown",
                    "device_fingerprint": getattr(agent, "fingerprint", lambda: "Unknown")() if agent else "Unknown",
                }
                self._global_ap_log.add(key)
                # Log event
                try:
                    with open(self.options["global_log_file"], "a") as f:
                        f.write(json.dumps(entry) + '\n')
                except Exception as e:
                    logging.error(f"[TripleGeo] Failed to log global AP map: {e}")
                # Send Discord webhook
                self.send_discord_webhook(entry)

    def on_handshake(self, agent, filename, access_point, client_station):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        handshake_entry = {
            "timestamp": time.time(),
            "ssid": getattr(access_point, 'ssid', None),
            "bssid": getattr(access_point, 'mac', None),
            "client": getattr(client_station, 'mac', "") if client_station else "",
            "rssi": getattr(access_point, 'rssi', "N/A"),
            "channel": getattr(access_point, 'channel', "N/A"),
            "encryption": getattr(access_point, 'encryption', "N/A"),
            "lat": gps_coord[0] if gps_coord else "N/A",
            "lon": gps_coord[1] if gps_coord else "N/A",
            "source": "gpsd" if gps_coord else "none",
            "vendor": oui_lookup(getattr(access_point, 'mac', "")),
            "google_maps": "https://www.google.com/maps/search/?api=1&query={},{}".format(gps_coord[0], gps_coord[1]) if gps_coord else "N/A",
            "handshake_file": filename,
            "pwnagotchi_name": getattr(agent, "name", lambda: "Unknown")() if agent else "Unknown",
            "device_fingerprint": getattr(agent, "fingerprint", lambda: "Unknown")() if agent else "Unknown",
        }
        # Save to .coord.json for downstream compatibility
        if gps_coord:
            gps_output = filename.replace(".pcap", ".triplegeo.coord.json")
            with open(gps_output, "w") as out:
                json.dump({"coord": {"lat": gps_coord[0], "lon": gps_coord[1]}, "source": "gpsd"}, out)
            logging.info(f"[TripleGeo] Saved GPS data for handshake to {gps_output}")
        else:
            logging.info("[TripleGeo] No GPS fix for handshake (will try API on connect).")
        self.pending.append(filename)
        self._save_pending()
        # Send Discord notification
        self.send_discord_webhook(handshake_entry)

    def send_discord_webhook(self, event):
        webhook_url = self.options.get("discord_webhook_url", "")
        if not webhook_url:
            return
        # Format timestamp
        import datetime
        ts_str = datetime.datetime.utcfromtimestamp(event["timestamp"]).strftime('%Y-%m-%d %H:%M:%S UTC')
        # Compose embed fields
        fields = [
            {"name": "SSID", "value": str(event.get("ssid", "")), "inline": True},
            {"name": "BSSID", "value": str(event.get("bssid", "")), "inline": True},
            {"name": "Client MAC", "value": str(event.get("client", "")), "inline": True},
            {"name": "Signal Strength", "value": f"{event.get('rssi', '?')} dBm", "inline": True},
            {"name": "Channel", "value": str(event.get("channel", "")), "inline": True},
            {"name": "Encryption", "value": str(event.get("encryption", "")), "inline": True},
            {"name": "Vendor", "value": str(event.get("vendor", "")), "inline": True},
            {"name": "Timestamp", "value": ts_str, "inline": True},
            {"name": "Geolocation", "value": f"[Google Maps]({event['google_maps']})", "inline": False},
            {"name": "Coordinates", "value": f"{event.get('lat','')},{event.get('lon','')}", "inline": True},
            {"name": "Geolocation Source", "value": str(event.get("source", "")), "inline": True},
            {"name": "Handshake File", "value": str(event.get("handshake_file", "")), "inline": False},
            {"name": "Pwnagotchi Name", "value": str(event.get("pwnagotchi_name", "")), "inline": True},
            {"name": "Fingerprint", "value": str(event.get("device_fingerprint", "")), "inline": True},
        ]
        data = {
            "embeds": [
                {
                    "title": ":satellite: New Wireless Event",
                    "description": "Pwnagotchi triplegeo detected a new AP, client, or handshake.",
                    "fields": fields,
                    "footer": {"text": f"triplegeo v{self.__version__}, Pwnagotchi Discord Notification"}
                }
            ]
        }
        try:
            resp = requests.post(webhook_url, json=data, timeout=10)
            if not resp.ok:
                logging.warning(f"[TripleGeo] Discord webhook failed: {resp.status_code} {resp.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] Discord webhook error: {e}")

    # ... (the rest of the original methods remain as above; not reprinted to save space)
