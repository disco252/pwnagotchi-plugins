import os
import json
import time
import threading
import logging
import requests
import asyncio
import pwnagotchi.plugins as plugins
from bleak import BleakScanner

# Attempt gpsd import
try:
    import gps
    HAS_GPSD = True
except ImportError:
    HAS_GPSD = False

class BLEWardrive(plugins.Plugin):
    __author__ = "YourName"
    __version__ = "1.1"
    __license__ = "GPL3"
    __description__ = (
        "Bluetooth LE wardriving plugin with GPS and Geolocation API support."
    )
    __name__ = "ble_wardrive"
    __defaults__ = {
        "enabled": False,
        "discord_webhook_url": "",
        "scan_interval": 10,
        "scan_duration": 5,
        "use_gpsd": True,
        "google_api_key": "",
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.loop = None
        self.stop_event = threading.Event()
        self.gps_session = None
        self.last_fix = None

    def on_loaded(self):
        for k, v in self.__defaults__.items():
            self.options.setdefault(k, v)
        if self.options["use_gpsd"] and HAS_GPSD:
            self._connect_gpsd()
        logging.info("[BLEWardrive] Loaded; GPSd=%s", bool(self.gps_session))
        threading.Thread(target=self._ble_loop, daemon=True).start()

    def _connect_gpsd(self):
        try:
            self.gps_session = gps.gps()  # connect to local gpsd
            logging.info("[BLEWardrive] Connected to gpsd")
        except Exception as e:
            self.gps_session = None
            logging.warning("[BLEWardrive] gpsd connection failed: %s", e)

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
                if rssi is not None:
                    self._report(device, adv, rssi)
            await asyncio.sleep(interval)

    def _report(self, device, adv, rssi):
        url = self.options["discord_webhook_url"]
        if not url:
            return

        # get timestamp
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # get GPS
        coord = self._get_gps_fix() if self.options["use_gpsd"] else None
        lat, lon, alt = ("N/A","N/A","N/A")
        src = "none"
        if coord:
            lat, lon, alt = coord[0], coord[1], coord[2] or "N/A"
            src = "gpsd"
        elif self.options["google_api_key"]:
            # fallback to Google Geolocation API using observed Wi-Fi/BLE points
            gl_url = "https://www.googleapis.com/geolocation/v1/geolocate"
            headers = {"Content-Type":"application/json"}
            payload = {"considerIp": True}
            try:
                res = requests.post(gl_url, params={"key":self.options["google_api_key"]},
                                    json=payload, timeout=5).json()
                loc = res.get("location", {})
                lat, lon = loc.get("lat","N/A"), loc.get("lng","N/A")
                src = "google"
            except Exception as e:
                logging.warning("[BLEWardrive] Google geoloc failed: %s", e)

        # build Discord embed fields
        fields = [
            {"name":"Address","value":device.address,"inline":True},
            {"name":"Name","value":device.name or "<Unknown>","inline":True},
            {"name":"RSSI","value":f"{rssi} dBm","inline":True},
            {"name":"Time","value":ts,"inline":True},
            {"name":"Latitude","value":str(lat),"inline":True},
            {"name":"Longitude","value":str(lon),"inline":True},
            {"name":"Altitude","value":str(alt),"inline":True},
            {"name":"Location Source","value":src,"inline":True},
            {"name":"Manufacturer Data","value":"; ".join(f"{m}: {bytes(v).hex()}" for m,v in (adv.manufacturer_data or {}).items()) or "None","inline":False},
        ]
        payload = {"embeds":[{"title":":satellite: BLE Device","fields":fields,"footer":{"text":f"ble_wardrive v{self.__version__}"}}]}

        try:
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logging.error("[BLEWardrive] Webhook error: %s", e)

    def on_unload(self, ui):
        self.stop_event.set()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        logging.info("[BLEWardrive] Unloaded.")
