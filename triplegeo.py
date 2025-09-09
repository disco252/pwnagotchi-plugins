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
        hd = self.options.get("handshake_dir", "/home/pi/handshakes")
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

                if coord_file.endswith(".triplegeo.coord.json"):
                    handshake_file = os.path.basename(coord_file).replace(".triplegeo.coord.json", ".pcap")
                    name = os.path.basename(coord_file).rsplit(".triplegeo.coord.json", 1)[0]
                else:
                    handshake_file = os.path.basename(coord_file).replace(".coord.json", ".pcap")
                    name = os.path.basename(coord_file).rsplit(".coord.json", 1)[0]

                ssid = name.split("_", 1)[0]

                event = {
                    "timestamp":         time.time(),
                    "ssid":              ssid,
                    "bssid":             "N/A",
                    "client":            "N/A",
                    "rssi":              "N/A",
                    "snr":               "N/A",
                    "channel":           "N/A",
                    "frequency":         "N/A",
                    "band":              "N/A",
                    "encryption":        "N/A",
                    "lat":               data.get("coord", {}).get("lat", "N/A"),
                    "lon":               data.get("coord", {}).get("lon", "N/A"),
                    "altitude":          data.get("coord", {}).get("altitude", "N/A"),
                    "source":            data.get("source", "unknown"),
                    "vendor":            "N/A",
                    "handshake_file":    handshake_file,
                    "supported_rates":            data.get("supported_rates", []),
                    "extended_supported_rates":   data.get("extended_supported_rates", []),
                    "vendor_specific_tags":       data.get("vendor_specific", {}),
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
                if report.get('class') == 'TPV' and getattr(report, 'mode', 1) >= 2 and hasattr(report, 'lat') and hasattr(report, 'lon'):
                    lat = float(report.lat)
                    lon = float(report.lon)
                    alt = getattr(report, 'alt', None)
                    if alt is not None:
                        self._gps_last = (lat, lon, float(alt))
                    else:
                        self._gps_last = (lat, lon)
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
                    pass  # implement Google API call
            elif method == "wigle":
                user, token = self.options["wigle_user"], self.options["wigle_token"]
                if user and token and data:
                    pass  # implement WiGLE API call
        return None, None

    def on_unfiltered_ap_list(self, agent, ap_list):
        logging.info(f"AP entry keys: {ap_list.keys()}")
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        now = time.time()
        for ap in ap_list:
            key = f"{ap.get('mac')}|{ap.get('hostname')}|{ap.get('client')}"
            if key not in self.processed:
                # SNR
                noise = ap.get("noise")
                rssi  = ap.get("rssi")
                snr   = "N/A"
                if isinstance(rssi, (int,float)) and isinstance(noise, (int,float)):
                    snr = rssi - noise
                # frequency & band
                freq = ap.get("frequency")
                band = "unknown"
                if isinstance(freq, (int,float)):
                    band = "2.4 GHz" if freq < 3000 else "5 GHz" if freq < 6000 else "6 GHz"
                entry = {
                    "timestamp":        now,
                    "ssid":             ap.get("hostname", "<unknown>"),
                    "bssid":            ap.get("mac", ""),
                    "client":           ap.get("client", ""),
                    "rssi":             rssi or "N/A",
                    "snr":              snr,
                    "channel":          ap.get("channel", "N/A"),
                    "frequency":        freq or "N/A",
                    "band":             band,
                    "encryption":       ap.get("encryption", "N/A"),
                    "lat":              gps_coord[0] if gps_coord else "N/A",
                    "lon":              gps_coord[1] if gps_coord else "N/A",
                    "altitude":         gps_coord[2] if gps_coord and len(gps_coord) > 2 else "N/A",
                    "source":           "gpsd" if gps_coord else "none",
                    "vendor":           oui_lookup(ap.get("mac", "")),
                    "supported_rates":            ap.get("supported_rates", []),
                    "extended_supported_rates":   ap.get("extended_supported_rates", []),
                    "vendor_specific_tags":       ap.get("vendor_specific", {}),
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
        shortname = os.path.basename(filename).replace(".pcap", "")
        ssid = shortname.split("_", 1)[0]
        noise = getattr(ap, "noise", None)
        rssi  = getattr(ap, "rssi", None)
        snr   = "N/A"
        if isinstance(rssi, (int,float)) and isinstance(noise, (int,float)):
            snr = rssi - noise
        freq = getattr(ap, "frequency", None)
        band = "unknown"
        if isinstance(freq, (int,float)):
            band = "2.4 GHz" if freq < 3000 else "5 GHz" if freq < 6000 else "6 GHz"

        entry = {
            "timestamp":        time.time(),
            "ssid":             ssid,
            "bssid":            getattr(ap, "mac", None),
            "client":           getattr(client, "mac", ""),
            "rssi":             rssi or "N/A",
            "snr":              snr,
            "channel":          getattr(ap, "channel", "N/A"),
            "frequency":        freq or "N/A",
            "band":             band,
            "encryption":       getattr(ap, "encryption", "N/A"),
            "lat":              gps_coord[0] if gps_coord else "N/A",
            "lon":              gps_coord[1] if gps_coord else "N/A",
            "altitude":         gps_coord[2] if gps_coord and len(gps_coord) > 2 else "N/A",
            "source":           "gpsd" if gps_coord else "none",
            "vendor":           oui_lookup(getattr(ap, "mac", "")),
            "handshake_file":   filename,
            "supported_rates":            getattr(ap, "supported_rates", []),
            "extended_supported_rates":   getattr(ap, "extended_supported_rates", []),
            "vendor_specific_tags":       getattr(ap, "vendor_specific", {}),
            "pwnagotchi_name":  getattr(agent, "name", lambda:"Unknown")(),
            "device_fingerprint": getattr(agent, "fingerprint", lambda:"Unknown")(),
        }
        if gps_coord:
            coord_file = filename.replace(".pcap", ".triplegeo.coord.json")
            coord_data = {"coord": {"lat": gps_coord[0], "lon": gps_coord[1]}, "source": "gpsd"}
            if len(gps_coord) > 2:
                coord_data["coord"]["altitude"] = gps_coord[2]
            with open(coord_file, "w") as f:
                json.dump(coord_data, f)
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

        rates = event.get("supported_rates", [])
        ext_rates = event.get("extended_supported_rates", [])
        all_rates = rates + ext_rates if isinstance(rates, list) and isinstance(ext_rates, list) else []
        rates_str = ", ".join([f"{r} Mbps" for r in all_rates[:5]]) if all_rates else "N/A"

        vendor_tags = event.get("vendor_specific_tags", {})
        vendor_str = ", ".join([f"{k}: {v}" for k, v in vendor_tags.items()][:3]) if vendor_tags else "N/A"

        fields = [
            {"name":"SSID","value":str(event["ssid"]),"inline":True},
            {"name":"BSSID","value":str(event["bssid"]),"inline":True},
            {"name":"Client","value":str(event.get("client","")),"inline":True},
            {"name":"Signal","value":f"{event.get('rssi','N/A')} dBm","inline":True},
            {"name":"SNR","value":f"{event.get('snr','N/A')} dB","inline":True},
            {"name":"Channel","value":str(event.get("channel","N/A")),"inline":True},
            {"name":"Frequency","value":f"{event.get('frequency','N/A')} MHz","inline":True},
            {"name":"Band","value":str(event.get("band","N/A")),"inline":True},
            {"name":"Encryption","value":str(event.get("encryption","N/A")),"inline":True},
            {"name":"Vendor","value":str(event.get("vendor","")),"inline":True},
            {"name":"Timestamp","value":ts,"inline":True},
            {"name":"Coordinates","value":f"{event.get('lat','N/A')},{event.get('lon','N/A')}","inline":True},
            {"name":"Altitude","value":f"{event.get('altitude','N/A')} m","inline":True},
            {"name":"Source","value":str(event.get("source","")),"inline":True},
            {"name":"Supported Rates","value":rates_str,"inline":False},
            {"name":"Vendor Tags","value":vendor_str,"inline":False},
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
