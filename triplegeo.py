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

def oui_lookup(mac):
    vendors = {
        "00:11:22": "VendorA Inc.",
        "AA:BB:CC": "VendorB Corp.",
    }
    return vendors.get(mac.upper()[:8], "Unknown")

class TripleGeo(plugins.Plugin):
    __author__ = "disco252"
    __version__ = "1.6"
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
        "global_log_file": "/root/triplegeo_globalaplog.jsonl",
        "discord_webhook_url": "",
    }

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
                with open(self.options["processed_file"]) as f:
                    self.processed = set(json.load(f))
        except Exception as e:
            logging.warning(f"[TripleGeo] {_e}")
        try:
            if os.path.exists(self.options["pending_file"]):
                with open(self.options["pending_file"]) as f:
                    self.pending = json.load(f)
        except Exception as e:
            logging.warning(f"[TripleGeo] {_e}")

    def _save_pending(self):
        try:
            with open(self.options["pending_file"], "w") as f:
                json.dump(self.pending, f)
        except Exception as e:
            logging.warning(f"[TripleGeo] {_e}")

    def connect_gpsd(self):
        if not HAS_GPSD:
            logging.warning("[TripleGeo] gpsd-py3 module not found; GPS disabled.")
            return
        try:
            # Connect via the default GPSD socket rather than host/port
            logging.info("[TripleGeo] Connecting to local gpsd socket")
            self.gps_session = gps.gps()  # no args → uses /var/run/gpsd.sock
            logging.info("[TripleGeo] Connected to gpsd for GPS.")
        except Exception as e:
            self.gps_session = None
            logging.warning(f"[TripleGeo] Could not connect to gpsd: {e}")

    def get_gps_coord(self, max_attempts=10):
        if not self.gps_session:
            return self._gps_last
        try:
            for _ in range(max_attempts):
                report = self.gps_session.next()
                if report.get('class') == 'TPV' and getattr(report, 'mode', 1) >= 2:
                    if hasattr(report, 'lat') and hasattr(report, 'lon'):
                        self._gps_last = (float(report.lat), float(report.lon))
                        return self._gps_last
        except Exception as e:
            logging.warning(f"[TripleGeo] GPS exception: {e}")
        return self._gps_last

    def on_unfiltered_ap_list(self, agent, ap_list):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        now = time.time()
        for ap in ap_list:
            key = f"{ap.get('mac')}|{ap.get('hostname')}|{ap.get('client')}"
            if key not in self._global_ap_log:
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
                    "google_maps": f"<https://www.google.com/maps/search/?api=1&query={gps_coord>[0]},{gps_coord[1]}" if gps_coord else "N/A",
                    "pwnagotchi_name": getattr(agent, "name", lambda:"Unknown")(),
                    "device_fingerprint": getattr(agent, "fingerprint", lambda:"Unknown")(),
                }
                self._global_ap_log.add(key)
                try:
                    with open(self.options["global_log_file"], "a") as f:
                        f.write(json.dumps(entry)+"\n")
                except Exception as e:
                    logging.error(f"[TripleGeo] Failed to log: {e}")
                self.send_discord_webhook(entry)

    def on_handshake(self, agent, filename, ap, client):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        entry = {
            "timestamp": time.time(),
            "ssid": getattr(ap,"ssid",None),
            "bssid": getattr(ap,"mac",None),
            "client": getattr(client,"mac",""),
            "rssi": getattr(ap,"rssi","N/A"),
            "channel": getattr(ap,"channel","N/A"),
            "encryption": getattr(ap,"encryption","N/A"),
            "lat": gps_coord[0] if gps_coord else "N/A",
            "lon": gps_coord[1] if gps_coord else "N/A",
            "source": "gpsd" if gps_coord else "none",
            "vendor": oui_lookup(getattr(ap,"mac","")),
            "google_maps": f"<https://www.google.com/maps/search/?api=1&query={gps_coord>[0]},{gps_coord[1]}" if gps_coord else "N/A",
            "handshake_file": filename,
            "pwnagotchi_name": getattr(agent,"name",lambda:"Unknown")(),
            "device_fingerprint": getattr(agent,"fingerprint",lambda:"Unknown")(),
        }
        if gps_coord:
            out = filename.replace(".pcap",".triplegeo.coord.json")
            with open(out,"w") as f:
                json.dump({"coord":{"lat":gps_coord[0],"lon":gps_coord[1]},"source":"gpsd"},f)
        self.pending.append(filename)
        self._save_pending()
        self.send_discord_webhook(entry)

    def send_discord_webhook(self, event):
        url = self.options.get("discord_webhook_url")
        if not url:
            return
        import datetime
        ts = datetime.datetime.utcfromtimestamp(event["timestamp"]).strftime('%Y-%m-%d %H:%M:%S UTC')
        fields = [
            {"name":"SSID","value":event["ssid"],"inline":True},
            {"name":"BSSID","value":event["bssid"],"inline":True},
            {"name":"Client","value":event["client"],"inline":True},
            {"name":"Signal","value":f"{event['rssi']} dBm","inline":True},
            {"name":"Channel","value":event["channel"],"inline":True},
            {"name":"Encryption","value":event["encryption"],"inline":True},
            {"name":"Vendor","value":event["vendor"],"inline":True},
            {"name":"Timestamp","value":ts,"inline":True},
            {"name":"Coordinates","value":f\"{event['lat']},{event['lon']}\","inline":True},
            {"name":"Source","value":event["source"],"inline":True},
            {"name":"File","value":event.get("handshake_file",""),"inline":False},
        ]
        payload={"embeds":[{"title":":satellite: New Event","fields":fields,"footer":{"text":f"triplegeo v{self.__version__}"}}]}
        try:
            r = requests.post(url,json=payload,timeout=10)
            if not r.ok:
                logging.warning(f"[TripleGeo] Webhook failed: {r.status_code} {r.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] Webhook error: {e}")
