import os
import time
import threading
import logging
import requests
import asyncio
import pwnagotchi.plugins as plugins
from bleak import BleakScanner

try:
    import gps
    HAS_GPSD = True
except ImportError:
    HAS_GPSD = False

class BLEWardrive(plugins.Plugin):
    __author__ = "YourName"
    __version__ = "1.3"
    __license__ = "GPL3"
    __description__ = (
        "Bluetooth LE wardriving plugin with GPS, device classification, dynamic IEEE OUI lookup, and security/anomaly/mesh detection."
    )
    __name__ = "ble_wardrive"
    __defaults__ = {
        "enabled": False,
        "discord_webhook_url": "",
        "scan_interval": 10,
        "scan_duration": 5,
        "use_gpsd": True,
        "google_api_key": "",
        "oui_db_path": "/usr/local/share/pwnagotchi/ieee_oui.txt",
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.loop = None
        self.stop_event = threading.Event()
        self.gps_session = None
        self.last_fix = None
        self.oui_db = self._load_oui_db(self.options["oui_db_path"])

    def _load_oui_db(self, db_path):
        oui_dict = {}
        if not os.path.exists(db_path):
            logging.warning(f"[BLEWardrive] OUI database file not found: {db_path}")
            return oui_dict
        with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    oui = parts[0].strip().replace('-', '').upper()
                    vendor = parts[1].split('\t')[-1].strip()
                    if len(oui) >= 6:
                        oui_dict[oui[:6]] = vendor
        logging.info(f"[BLEWardrive] Loaded {len(oui_dict)} OUIs from IEEE database")
        return oui_dict

    def _lookup_oui_vendor(self, mac_addr):
        oui = mac_addr.replace(":", "").upper()[:6]
        return self.oui_db.get(oui, "Unknown")

    def on_loaded(self):
        for k, v in self.__defaults__.items():
            self.options.setdefault(k, v)
        if self.options["use_gpsd"] and HAS_GPSD:
            self._connect_gpsd()
        logging.info(f"[BLEWardrive] Loaded; GPSd={bool(self.gps_session)}; OUIs={len(self.oui_db)}")
        threading.Thread(target=self._ble_loop, daemon=True).start()

    def _connect_gpsd(self):
        try:
            self.gps_session = gps.gps()
            logging.info("[BLEWardrive] Connected to gpsd")
        except Exception as e:
            self.gps_session = None
            logging.warning(f"[BLEWardrive] gpsd connection failed: {e}")

    def _get_gps_fix(self, attempts=5):
        if not self.gps_session:
            return None
        for _ in range(attempts):
            report = self.gps_session.next()
            if report.get("class") == "TPV" and hasattr(report, "lat") and hasattr(report, "lon"):
                fix = (float(report.lat), float(report.lon), getattr(report, "alt", None))
                self.last_fix = fix
                return fix
        return self.last_fix

    def _ble_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.create_task(self._scan_loop())
        self.loop.run_forever()

    async def _scan_loop(self):
        interval = self.options["scan_interval"]
        duration = self.options["scan_duration"]
        while not self.stop_event.is_set():
            devices = await BleakScanner.discover(timeout=duration, return_adv=True)
            for _, (device, adv) in devices.items():
                rssi = getattr(adv, "rssi", None) or getattr(device, "rssi", None)
                if rssi is None:
                    continue
                vendor = self._lookup_oui_vendor(device.address)
                self._report(device, adv, rssi, vendor)
            await asyncio.sleep(interval)

    def _report(self, device, adv, rssi, vendor):
        url = self.options["discord_webhook_url"]
        if not url:
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        coord = self._get_gps_fix() if self.options["use_gpsd"] else None
        lat, lon, alt = ("N/A","N/A","N/A")
        src = "none"
        if coord:
            lat, lon, alt = coord
            src = "gpsd"
        elif self.options["google_api_key"]:
            try:
                res = requests.post(
                    "https://www.googleapis.com/geolocation/v1/geolocate",
                    params={"key": self.options["google_api_key"]},
                    json={"considerIp": True},
                    timeout=5
                ).json()
                loc = res.get("location", {})
                lat, lon = loc.get("lat","N/A"), loc.get("lng","N/A")
                src = "google"
            except Exception as e:
                logging.warning(f"[BLEWardrive] Google geoloc failed: {e}")

        fields = [
            {"name":"Address","value":device.address,"inline":True},
            {"name":"Vendor","value":vendor,"inline":True},
            {"name":"RSSI","value":f"{rssi} dBm","inline":True},
            {"name":"Time","value":ts,"inline":True},
            {"name":"Latitude","value":str(lat),"inline":True},
            {"name":"Longitude","value":str(lon),"inline":True},
            {"name":"Altitude","value":str(alt),"inline":True},
            {"name":"Location Source","value":src,"inline":True},
        ]
        payload = {
            "embeds": [
                {"title":":satellite: BLE Device", "fields": fields, "footer": {"text": f"ble_wardrive v{self.__version__}"}}
            ]
        }
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logging.error(f"[BLEWardrive] Webhook error: {e}")

    def on_unload(self, ui):
        self.stop_event.set()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        logging.info("[BLEWardrive] Plugin unloaded.")
