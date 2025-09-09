import logging
import requests
import os
import json
import time
import threading

import pwnagotchi.plugins as plugins

def oui_lookup(mac):
    vendors = {
        "00:11:22": "VendorA Inc.",
        "AA:BB:CC": "VendorB Corp.",
    }
    return vendors.get(mac.upper()[:8], "Unknown")

class TripleGeo(plugins.Plugin):
    __author__ = "disco252"
    __version__ = "1.8"
    __license__ = "GPL3"
    __description__ = (
        "Geolocation via GPS, Google, or Wigle; posts handshake events to Discord."
    )
    __defaults__ = {
        "enabled":          False,
        "mode":             ["gps","google","wigle"],
        "gps_timeout":      5,        # seconds to wait for GPS fix
        "google_api_key":   "",
        "wigle_user":       "",
        "wigle_token":      "",
        "handshake_dir":    "/home/pi/handshakes",
        "processed_file":   "/root/.triplegeo_processed",
        "discord_webhook_url": "",
        "global_log_file":  "/root/triplegeo_globalaplog.jsonl",
        "wigle_delay":      2,
        "max_wigle_per_minute": 10,
    }

    def __init__(self):
        super().__init__()
        self.processed = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self._load_processed()

    def _load_processed(self):
        try:
            with open(self.options["processed_file"]) as f:
                self.processed = set(json.load(f))
        except FileNotFoundError:
            self.processed = set()
        except Exception as e:
            logging.warning(f"[TripleGeo] load processed: {e}")

    def _save_processed(self):
        try:
            with open(self.options["processed_file"], "w") as f:
                json.dump(list(self.processed), f)
        except Exception as e:
            logging.warning(f"[TripleGeo] save processed: {e}")

    def on_internet_available(self, agent):
        """Process new .net-pos.json handshake files."""
        hd = self.options["handshake_dir"]
        try:
            files = sorted(f for f in os.listdir(hd) if f.endswith(".net-pos.json"))
        except Exception as e:
            logging.error(f"[TripleGeo] handshake_dir error: {e}")
            return

        new = [f for f in files if f not in self.processed]
        if not new:
            return

        for fname in new:
            path = os.path.join(hd, fname)
            try:
                with open(path) as f:
                    data = json.load(f)
            except Exception as e:
                logging.warning(f"[TripleGeo] open {fname}: {e}")
                self.processed.add(fname)
                continue

            coord, source = self._geolocate(data)
            event = {
                "timestamp": time.time(),
                "ssid":      data["wifiAccessPoints"][0].get("ssid","N/A"),
                "bssid":     data["wifiAccessPoints"][0].get("macAddress",""),
                "lat":       coord[0],
                "lon":       coord[1],
                "source":    source,
                "vendor":    oui_lookup(data["wifiAccessPoints"][0].get("macAddress","")),
                "file":      fname,
            }

            self._log_global(event)
            self._post_discord(event)
            self.processed.add(fname)

        self._save_processed()

    def _geolocate(self, data):
        """Attempt GPS, then Google, then Wigle in order."""
        for method in self.options["mode"]:
            if method == "gps":
                coord = self._try_gps()
                if coord:
                    return coord, "gps"
            if method == "google" and self.options["google_api_key"]:
                coord = self._google_loc(data)
                if coord:
                    return coord, "google"
            if method == "wigle" and self.options["wigle_user"]:
                coord = self._wigle_loc(data)
                if coord:
                    return coord, "wigle"
        return ("N/A","N/A"), "none"

    def _try_gps(self):
        """Non-blocking GPS fix with timeout."""
        try:
            import gps
            session = gps.gps()
            deadline = time.time() + self.options["gps_timeout"]
            while time.time() < deadline:
                report = session.next()
                if report.get("class") == "TPV" and getattr(report, "mode", 1) >= 2:
                    if hasattr(report, "lat") and hasattr(report, "lon"):
                        return (float(report.lat), float(report.lon))
        except Exception:
            pass
        return None

    def _google_loc(self, data):
        url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={self.options['google_api_key']}"
        try:
            r = self.session.post(url, json={"wifiAccessPoints": data["wifiAccessPoints"]}, timeout=10)
            r.raise_for_status()
            loc = r.json().get("location")
            return (loc["lat"], loc["lng"])
        except Exception as e:
            logging.warning(f"[TripleGeo] Google failed: {e}")
            return None

    def _wigle_loc(self, data):
        url = "https://api.wigle.net/api/v2/geo"
        auth = (self.options["wigle_user"], self.options["wigle_token"])
        try:
            bssids = [ap["macAddress"] for ap in data["wifiAccessPoints"]]
            r = self.session.post(url, auth=auth, json={"netids": bssids}, timeout=10)
            r.raise_for_status()
            res = r.json()
            if res.get("results"):
                return (res["results"][0]["trilat"], res["results"][0]["trilong"])
        except Exception as e:
            logging.warning(f"[TripleGeo] Wigle failed: {e}")
        return None

    def _log_global(self, ev):
        try:
            with open(self.options["global_log_file"], "a") as f:
                f.write(json.dumps(ev)+"\n")
        except Exception as e:
            logging.error(f"[TripleGeo] global log: {e}")

    def _post_discord(self, ev):
        url = self.options.get("discord_webhook_url")
        if not url:
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ev["timestamp"]))
        fields = [
            {"name":"SSID","value":ev["ssid"],"inline":True},
            {"name":"BSSID","value":ev["bssid"],"inline":True},
            {"name":"Coordinates","value":f"{ev['lat']},{ev['lon']}","inline":True},
            {"name":"Source","value":ev["source"],"inline":True},
            {"name":"Vendor","value":ev["vendor"],"inline":True},
            {"name":"Timestamp","value":ts,"inline":False},
            {"name":"File","value":ev["file"],"inline":False},
        ]
        payload = {"embeds":[{"title":":satellite: New Handshake","fields":fields}]}
        try:
            r = self.session.post(url, json=payload, timeout=10)
            if not r.ok:
                logging.warning(f"[TripleGeo] Webhook error: {r.status_code} {r.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] Webhook exception: {e}")
