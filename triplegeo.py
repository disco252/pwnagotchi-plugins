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
    __version__ = "1.7"
    __license__ = "GPL3"
    __description__ = (
        "Advanced geolocation via GPS, Google, or Wigle; posts events to Discord."
    )
    __defaults__ = {
        "enabled":         False,
        "mode":            ["gps","google","wigle"],  # order of fallback
        "google_api_key":  "",
        "wigle_user":      "",
        "wigle_token":     "",
        "handshake_dir":   "/home/pi/handshakes",
        "processed_file":  "/root/.triplegeo_processed",
        "discord_webhook_url":"",
        "global_log_file": "/root/triplegeo_globalaplog.jsonl",
        "wigle_delay":      2,
        "max_wigle_per_minute":10,
    }

    def __init__(self):
        super().__init__()
        self.processed = set()
        self.lock = threading.Lock()
        self._load_processed()
        self.session = requests.Session()

    def _load_processed(self):
        try:
            if os.path.exists(self.options["processed_file"]):
                with open(self.options["processed_file"]) as f:
                    self.processed = set(json.load(f))
        except Exception as e:
            logging.warning(f"[TripleGeo] load processed: {e}")

    def _save_processed(self):
        try:
            with open(self.options["processed_file"], "w") as f:
                json.dump(list(self.processed), f)
        except Exception as e:
            logging.warning(f"[TripleGeo] save processed: {e}")

    def on_internet_available(self, agent):
        """Process any new .net-pos.json handshake files."""
        hd = self.options["handshake_dir"]
        files = sorted(f for f in os.listdir(hd) if f.endswith(".net-pos.json"))
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

            # Determine geolocation via configured mode
            coord, source = self._geolocate(data)
            event = {
                "timestamp": time.time(),
                "ssid":      data.get("wifiAccessPoints",[])[0].get("ssid","N/A") if data.get("wifiAccessPoints") else "N/A",
                "bssid":     data.get("wifiAccessPoints",[])[0].get("macAddress",""),
                "lat":       coord[0],
                "lon":       coord[1],
                "source":    source,
                "vendor":    oui_lookup(data.get("wifiAccessPoints",[])[0].get("macAddress","")),
                "file":      fname,
            }

            self._log_global(event)
            self._post_discord(event)
            self.processed.add(fname)

        self._save_processed()

    def _geolocate(self, netpos_json):
        """Try gpsd? (skipped), then Google, then Wigle."""
        for m in self.options["mode"]:
            if m == "google" and self.options["google_api_key"]:
                coord = self._google_loc(netpos_json)
                if coord:
                    return coord, "google"
            if m == "wigle" and self.options["wigle_user"]:
                coord = self._wigle_loc(netpos_json)
                if coord:
                    return coord, "wigle"
            # gps mode is no-op here; we skip it if no gpsd module
        return ("N/A","N/A"), "none"

    def _google_loc(self, data):
        url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={self.options['google_api_key']}"
        try:
            r = self.session.post(url, json={"wifiAccessPoints": data["wifiAccessPoints"]}, timeout=10)
            r.raise_for_status()
            j = r.json().get("location")
            return (j["lat"], j["lng"])
        except Exception as e:
            logging.warning(f"[TripleGeo] Google geolocate failed: {e}")
            return None

    def _wigle_loc(self, data):
        # Simple Wigle API wrapper
        url = "https://api.wigle.net/api/v2/geo"
        auth = (self.options["wigle_user"], self.options["wigle_token"])
        try:
            # only send BSSID list
            bssids = [ap["macAddress"] for ap in data["wifiAccessPoints"]]
            r = self.session.post(url, auth=auth, json={"netids": bssids}, timeout=10)
            r.raise_for_status()
            res = r.json()
            if res.get("results"):
                lat = res["results"][0]["trilat"]
                lon = res["results"][0]["trilong"]
                return (lat, lon)
        except Exception as e:
            logging.warning(f"[TripleGeo] Wigle geolocate failed: {e}")
        return None

    def _log_global(self, event):
        try:
            with open(self.options["global_log_file"], "a") as f:
                f.write(json.dumps(event)+"\n")
        except Exception as e:
            logging.error(f"[TripleGeo] failed global log: {e}")

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
            r = self.session.post(url,json=payload,timeout=10)
            if not r.ok:
                logging.warning(f"[TripleGeo] Webhook error: {r.status_code} {r.text}")
        except Exception as e:
            logging.error(f"[TripleGeo] Webhook exception: {e}")
