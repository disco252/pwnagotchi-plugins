import logging
import requests
import os
import json
import time
import threading
import glob
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
    return vendors.get((mac or "").upper()[:8], "Unknown")

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
        "enabled":             False,
        "mode":                ["gps", "google", "wigle"],
        "google_api_key":      "",
        "wigle_user":          "",
        "wigle_token":         "",
        "handshake_dir":       "/home/pi/handshakes",
        "processed_file":      "/root/.triplegeo_processed",
        "pending_file":        "/root/.triplegeo_pending",
        "wigle_delay":         2,
        "max_wigle_per_minute": 10,
        "wigle_upload":        True,
        "global_log_file":     "/root/triplegeo_globalaplog.jsonl",
        "discord_webhook_url": "",
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.api_mutex   = threading.Lock()
        self.processed   = set()
        self.pending     = []
        self.gps_session = None
        self._gps_last   = None

    def on_loaded(self):
        for key, val in self.__defaults__.items():
            self.options.setdefault(key, val)
        self._load_storage()
        self._connect_gpsd()
        logging.info("[TripleGeo] Plugin loaded successfully.")
        self._report_existing_coords()

    def _report_existing_coords(self):
        logging.info(f"[TripleGeo] discord_webhook_url={self.options.get('discord_webhook_url')}")
        """
        Send Discord messages for all existing .coord.json files
        in handshake_dir at plugin startup.
        """
        hd = self.options.get("handshake_dir", "/home/pi/handshakes")
        # match both *.coord.json and *.triplegeo.coord.json
        patterns = [
            os.path.join(hd, "*.triplegeo.coord.json"),
            os.path.join(hd, "*.coord.json")
        ]
        files = []
        for pattern in patterns:
            files.extend(glob.glob(pattern))
        if not files:
            logging.info("[TripleGeo] No existing coord.json files to report.")
            return
        logging.info(f"[TripleGeo] Reporting {len(files)} existing coord.json files.")
        for coord_file in files:
            try:
                with open(coord_file) as f:
                    data = json.load(f)
                # determine handshake filename and extract SSID
                if coord_file.endswith(".triplegeo.coord.json"):
                    handshake_file = os.path.basename(coord_file).replace(".triplegeo.coord.json", ".pcap")
                    name = os.path.basename(coord_file).rsplit(".triplegeo.coord.json", 1)[0]
                else:
                    handshake_file = os.path.basename(coord_file).replace(".coord.json", ".pcap")
                    name = os.path.basename(coord_file).rsplit(".coord.json", 1)[0]
                
                # Extract SSID from filename (part before first underscore)
                ssid = name.split("_", 1)[0]
                
                event = {
                    "timestamp":         time.time(),
                    "ssid":              ssid,  # Now extracts from filename
                    "bssid":             "N/A",
                    "client":            "N/A",
                    "rssi":              "N/A",
                    "channel":           "N/A",
                    "encryption":        "N/A",
                    "lat":               data.get("coord", {}).get("lat", "N/A"),
                    "lon":               data.get("coord", {}).get("lon", "N/A"),
                    "source":            data.get("source", "unknown"),
                    "vendor":            "N/A",
                    "handshake_file":    handshake_file,
                    "pwnagotchi_name":   getattr(self, "name", lambda:"Unknown")(),
                    "device_fingerprint":getattr(self, "fingerprint", lambda:"Unknown")(),
                }
                self.send_discord_webhook(event, title=":file_folder: Existing Handshake")
            except Exception as e:
                logging.warning(f"[TripleGeo] Failed to report existing coord file {coord_file}: {e}")

    def _load_storage(self):
        pf = self.options["processed_file"]
        if os.path.exists(pf):
            try:
                with open(pf) as f:
                    self.processed = set(json.load(f))
            except Exception as e:
                logging.warning(f"[TripleGeo] load processed: {e}")
        pend = self.options["pending_file"]
        if os.path.exists(pend):
            try:
                with open(pend) as f:
                    self.pending = json.load(f)
            except Exception as e:
                logging.warning(f"[TripleGeo] load pending: {e}")

    def _save_pending(self):
        try:
            with open(self.options["pending_file"], "w") as f:
                json.dump(self.pending, f)
        except Exception as e:
            logging.warning(f"[TripleGeo] save pending: {e}")

    def _connect_gpsd(self):
        if not HAS_GPSD:
            logging.warning("[TripleGeo] gpsd-py3 module not found; GPS disabled.")
            return
        try:
            logging.info("[TripleGeo] Connecting to local gpsd socket")
            self.gps_session = gps.gps()
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

    def _geolocate(self, data):
        for method in self.options["mode"]:
            if method == "gps":
                coord = self.get_gps_coord()
                if coord:
                    return coord, "gps"
            elif method == "google":
                key = self.options["google_api_key"]
                if key and data:
                    # implement Google API call
                    pass
            elif method == "wigle":
                user, token = self.options["wigle_user"], self.options["wigle_token"]
                if user and token and data:
                    # implement WiGLE API call
                    pass
        return None, None

    def on_unfiltered_ap_list(self, agent, ap_list):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        now = time.time()
        for ap in ap_list:
            key = f"{ap.get('mac')}|{ap.get('hostname')}|{ap.get('client')}"
            if key not in self.processed:
                entry = {
                    "timestamp":        now,
                    "ssid":             ap.get("hostname", "<unknown>"),
                    "bssid":            ap.get("mac", ""),
                    "client":           ap.get("client", ""),
                    "rssi":             ap.get("rssi", "N/A"),
                    "channel":          ap.get("channel", "N/A"),
                    "encryption":       ap.get("encryption", "N/A"),
                    "lat":              gps_coord[0] if gps_coord else "N/A",
                    "lon":              gps_coord[1] if gps_coord else "N/A",
                    "source":           "gpsd" if gps_coord else "none",
                    "vendor":           oui_lookup(ap.get("mac", "")),
                    "pwnagotchi_name":  getattr(agent, "name", lambda:"Unknown")(),
                    "device_fingerprint": getattr(agent, "fingerprint", lambda:"Unknown")(),
                }
                self.processed.add(key)
                try:
                    with open(self.options["global_log_file"], "a") as f:
                        f.write(json.dumps(entry) + "\n")
                except Exception as e:
                    logging.error(f"[TripleGeo] Failed to log: {e}")
                self.send_discord_webhook(entry)

    def on_handshake(self, agent, filename, ap, client):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        
        # Extract SSID from handshake filename
        shortname = os.path.basename(filename).replace(".pcap", "")
        ssid = shortname.split("_", 1)[0]
        
        entry = {
            "timestamp":        time.time(),
            "ssid":             ssid,  # Now extracts from filename
            "bssid":            getattr(ap, "mac", None),
            "client":           getattr(client, "mac", ""),
            "rssi":             getattr(ap, "rssi", "N/A"),
            "channel":          getattr(ap, "channel", "N/A"),
            "encryption":       getattr(ap, "encryption", "N/A"),
            "lat":              gps_coord[0] if gps_coord else "N/A",
            "lon":              gps_coord[1] if gps_coord else "N/A",
            "source":           "gpsd" if gps_coord else "none",
            "vendor":           oui_lookup(getattr(ap, "mac", "")),
            "handshake_file":   filename,
            "pwnagotchi_name":  getattr(agent, "name", lambda:"Unknown")(),
            "device_fingerprint": getattr(agent, "fingerprint", lambda:"Unknown")(),
        }
        if gps_coord:
            coord_file = filename.replace(".pcap", ".triplegeo.coord.json")
            with open(coord_file, "w") as f:
                json.dump({"coord": {"lat": gps_coord[0], "lon": gps_coord[1]}, "source": "gpsd"}, f)
        self.pending.append(filename)
        self._save_pending()
        self.send_discord_webhook(entry)

    def send_discord_webhook(self, event, title=":satellite: New Event"):
        url = self.options.get("discord_webhook_url", "")
        if not url:
            logging.error("[TripleGeo] No Discord webhook URL set in config.toml")
            return
        logging.info(f"[TripleGeo] Sending webhook to {url}")
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(event["timestamp"]))
        fields = [
            {"name":"SSID","value":str(event["ssid"]),"inline":True},
            {"name":"BSSID","value":str(event["bssid"]),"inline":True},
            {"name":"Client","value":str(event.get("client","")),"inline":True},
            {"name":"Signal","value":f"{event.get('rssi','N/A')} dBm","inline":True},
            {"name":"Channel","value":str(event.get("channel","N/A")),"inline":True},
            {"name":"Encryption","value":str(event.get("encryption","N/A")),"inline":True},
            {"name":"Vendor","value":str(event.get("vendor","")),"inline":True},
            {"name":"Timestamp","value":ts,"inline":True},
            {"name":"Coordinates","value":f"{event.get('lat','N/A')},{event.get('lon','N/A')}","inline":True},
            {"name":"Source","value":str(event.get("source","")),"inline":True},
            {"name":"File","value":str(event.get("handshake_file","")),"inline":False},
        ]
        payload = {
            "embeds": [
                {
                    "title": title,
                    "fields": fields,
                    "footer": {"text": f"triplegeo v{self.__version__}"}
                }
            ]
        }
        try:
            r = requests.post(url, json=payload, timeout=10)
            logging.info(f"[TripleGeo] Discord response: {r.status_code} {r.text}")
            if not r.ok:
                logging.warning(f"[TripleGeo] Webhook failed: {r.status_code} {r.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] Webhook error: {e}")
