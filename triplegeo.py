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

class TripleGeo(plugins.Plugin):
    __author__ = "disco252"
    __version__ = "1.4"
    __license__ = "GPL3"
    __description__ = (
        "Geolocation plugin for Pwnagotchi: uses GPS dongle, Google API, or WiGLE API for locating WiFi handshakes. "
        "Can upload data to WiGLE for wardriving. GPS, Google, WiGLE: triple fallback."
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
        "wigle_upload": True,  # New flag: enable/disable automatic WiGLE upload
        "gpsd_host": "localhost",
        "gpsd_port": 2947
    }

    GOOGLE_API_URL = "https://www.googleapis.com/geolocation/v1/geolocate?key={api}"
    WIGLE_API_URL = "https://api.wigle.net/api/v2/network/search"
    WIGLE_UPLOAD_URL = "https://api.wigle.net/api/v2/network/upload"

    def __init__(self):
        super().__init__()
        self.api_mutex = threading.Lock()
        self.processed = set()
        self.pending = []
        self.gps_session = None
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
            return None
        try:
            count = 0
            while count < max_attempts:
                report = self.gps_session.next()
                if report.get('class') == 'TPV' and getattr(report, 'mode', 1) >= 2:
                    if hasattr(report, 'lat') and hasattr(report, 'lon'):
                        return (float(report.lat), float(report.lon))
                count += 1
        except Exception as e:
            logging.warning(f"[TripleGeo] GPS exception: {e}")
        return None

    def _mark_processed(self, fname):
        self.processed.add(fname)
        try:
            with open(self.options["processed_file"], "w") as f:
                json.dump(list(self.processed), f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Couldn't update processed list: {e}")

    def _save_pending(self):
        try:
            with open(self.options["pending_file"], "w") as f:
                json.dump(self.pending, f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Couldn't update pending queue: {e}")

    def on_handshake(self, agent, filename, access_point, client_station):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        if gps_coord:
            gps_output = filename.replace(".pcap", ".triplegeo.coord.json")
            with open(gps_output, "w") as out:
                json.dump({"coord": {"lat": gps_coord[0], "lon": gps_coord[1]}, "source": "gpsd"}, out)
            logging.info(f"[TripleGeo] Saved GPS data for handshake to {gps_output}")
        else:
            logging.info("[TripleGeo] No GPS fix for handshake (will try API on connect).")
        self.pending.append(filename)
        self._save_pending()

    def on_internet_available(self, agent):
        with self.api_mutex:
            self.connect_gpsd()
            hs_dir = self.options.get("handshake_dir", "/home/pi/handshakes")
            try:
                files = [f for f in os.listdir(hs_dir)
                         if f.endswith(".net-pos.json") and f not in self.processed]
            except Exception as e:
                logging.error(f"[TripleGeo] Failed to read handshake dir: {e}")
                return
            wigle_calls = 0
            start_time = time.time()
            for fname in files:
                fpath = os.path.join(hs_dir, fname)
                try:
                    with open(fpath, "r") as f:
                        ap_json = json.load(f)
                except Exception as e:
                    logging.error(f"[TripleGeo] Can't read {fpath}: {e}")
                    self._mark_processed(fname)
                    continue
                coord_tag = self.get_coord_tag(ap_json, wigle_calls, start_time)
                coord_json = fpath.replace(".net-pos.json", ".coord.json")
                with open(coord_json, "w") as out:
                    json.dump({"coord": coord_tag}, out)
                self.maybe_upload_to_wigle(fpath)
                self._mark_processed(fname)
                if fname in self.pending:
                    self.pending.remove(fname)
                    self._save_pending()
            for pending_path in list(self.pending):
                if os.path.exists(pending_path):
                    self.maybe_upload_to_wigle(pending_path)
                    self.pending.remove(pending_path)
                    self._save_pending()

    def get_coord_tag(self, ap_json, wigle_calls, start_time):
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        if gps_coord:
            logging.info(f"[TripleGeo] Used GPS: lat={gps_coord[0]}, lon={gps_coord[1]}")
            return {"lat": gps_coord[0], "lon": gps_coord[1], "source": "gpsd"}
        google_loc = self.query_google(ap_json)
        if google_loc:
            logging.info(f"[TripleGeo] Google: {google_loc}")
            return {"lat": google_loc["lat"], "lon": google_loc["lng"], "source": "google"}
        bssids = [ap["macAddress"] for ap in ap_json.get("wifiAccessPoints", [])]
        wigle_locs, hits = [], 0
        for bssid in bssids:
            if wigle_calls >= self.options["max_wigle_per_minute"]:
                elapsed = time.time() - start_time
                wait = max(60 - elapsed, 0)
                if wait > 0:
                    logging.info(f"[TripleGeo] Waiting {int(wait)}s for WiGLE rate reset")
                    time.sleep(wait)
                wigle_calls, start_time = 0, time.time()
            loc = self.query_wigle(bssid)
            wigle_calls += 1
            if loc:
                hits += 1
                wigle_locs.append((loc["trilat"], loc["trilong"]))
            time.sleep(self.options["wigle_delay"])
        if hits:
            avg_lat = sum(float(x[0]) for x in wigle_locs) / hits
            avg_lon = sum(float(x[1]) for x in wigle_locs) / hits
            logging.info(f"[TripleGeo] WiGLE avg: lat={avg_lat:.6f}, lon={avg_lon:.6f}")
            return {"lat": avg_lat, "lon": avg_lon, "source": "wigle"}
        logging.info("[TripleGeo] No geolocation available for this handshake.")
        return {"lat": None, "lon": None, "source": "none"}

    def query_google(self, ap_json):
        key = self.options.get("google_api_key", "")
        if not key:
            logging.warning("[TripleGeo] Google API key not set")
            return None
        url = self.GOOGLE_API_URL.format(api=key)
        try:
            resp = requests.post(url, json=ap_json, timeout=10)
            if resp.ok:
                return resp.json().get("location", None)
            else:
                logging.warning(f"[TripleGeo] Google API error: {resp.status_code} {resp.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] Google API error: {e}")
        return None

    def query_wigle(self, bssid):
        user = self.options.get("wigle_user")
        token = self.options.get("wigle_token")
        if not user or not token:
            logging.warning("[TripleGeo] WiGLE credentials not set")
            return None
        headers = {
            "Authorization": "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
        }
        params = {"netid": bssid}
        try:
            resp = requests.get(self.WIGLE_API_URL, headers=headers, params=params, timeout=15)
            if resp.ok:
                results = resp.json().get("results", [])
                if results:
                    return results[0]
                return None
            else:
                logging.warning(f"[TripleGeo] WiGLE API error: {resp.status_code} {resp.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] WiGLE API (bssid {bssid}) error: {e}")
        return None

    def maybe_upload_to_wigle(self, file_path):
        """Uploads to WiGLE only if wigle_upload is True."""
        if not self.options.get("wigle_upload", True):
            logging.info("[TripleGeo] WiGLE upload is disabled by config; skipping upload.")
            return
        self.upload_to_wigle(file_path)

    def upload_to_wigle(self, file_path):
        user = self.options.get("wigle_user")
        token = self.options.get("wigle_token")
        if not user or not token:
            logging.warning("[TripleGeo] WiGLE credentials not set for upload")
            return
        headers = {
            "Authorization": "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
        }
        try:
            with open(file_path, "rb") as f:
                files = {'file': f}
                resp = requests.post(self.WIGLE_UPLOAD_URL, headers=headers, files=files, timeout=30)
            if resp.ok:
                logging.info("[TripleGeo] Uploaded scan to WiGLE successfully")
            else:
                logging.warning(f"[TripleGeo] WiGLE upload failed: {resp.status_code} {resp.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] WiGLE upload error: {e}")
