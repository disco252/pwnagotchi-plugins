import os
import json
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
    __version__ = "1.2"
    __license__ = "GPL3"
    __description__ = (
        "Bluetooth LE wardriving plugin with GPS, device classification, security, anomaly, and mesh network detection."
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
        self.known_rogue_ouis = {"00:11:22", "AA:BB:CC"}  # Example blacklist, expand this

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
            # Mesh network detection
            mesh_devices = self._detect_mesh_networks(devices)
            for _, (device, adv) in devices.items():
                rssi = getattr(adv, "rssi", None) or getattr(device, "rssi", None)
                if rssi is not None:
                    # Feature integration
                    classification = self._classify_device(device, adv)
                    vulnerabilities = self._detect_vulnerabilities(device, adv)
                    anomalies = self._detect_anomalies(device, adv)
                    rogue = self._detect_rogue_device(device)
                    is_mesh = device in mesh_devices
                    self._report(device, adv, rssi, classification, vulnerabilities, anomalies, rogue, is_mesh)
            await asyncio.sleep(interval)

    def _classify_device(self, device, adv):
        # Example fingerprinting and classification logic.
        mfg = adv.manufacturer_data or {}
        if 0x004C in mfg:  # Apple OUI
            return "Apple Device"
        elif 0x00E0 in mfg:  # Google
            return "Android/Google Device"
        elif device.name:
            ln = device.name.lower()
            if "fitbit" in ln:
                return "Fitness Tracker"
            elif "temp" in ln or "sensor" in ln:
                return "IoT Sensor"
        return "Unknown"

    def _detect_mesh_networks(self, devices):
        # Mesh provisioning/proxy UUIDs (Bluetooth SIG)
        mesh_uuids = {"00001827-0000-1000-8000-00805f9b34fb", "00001828-0000-1000-8000-00805f9b34fb"}
        mesh_devices = []
        for _, (device, adv) in devices.items():
            service_uuids = set(adv.service_uuids or [])
            if service_uuids.intersection(mesh_uuids):
                mesh_devices.append(device)
        return mesh_devices

    def _detect_vulnerabilities(self, device, adv):
        vulns = []
        # Exposed Generic Access service
        if adv.service_uuids and "00001800-0000-1000-8000-00805f9b34fb" in adv.service_uuids:
            vulns.append("Exposed Generic Access Service")
        # Static MAC check
        if self._is_static_mac(device.address):
            vulns.append("Static MAC Address (trackable)")
        # Check weak names
        if device.name and any(x in device.name.lower() for x in ("default", "test", "demo")):
            vulns.append("Weak Device Name")
        return vulns or ["None"]

    def _detect_anomalies(self, device, adv):
        alerts = []
        # Example: Unusual advertising intervals (looks for fast, repetitive advertisements)
        interval = getattr(adv, "interval", None)
        if interval is not None and interval < 20:
            alerts.append("Unusually short advertising interval")
        # Example: Manufacturer data length anomaly
        mfg = adv.manufacturer_data or {}
        for v in mfg.values():
            if len(v) > 32:
                alerts.append("Abnormally large manufacturer data")
        return alerts or ["None"]

    def _detect_rogue_device(self, device):
        # Example OUI blacklist check
        mac = device.address.replace(":", "").upper()
        oui = mac[:6]
        if oui in self.known_rogue_ouis:
            return "YES"
        return "NO"

    def _is_static_mac(self, mac):
        # Simple static/random MAC detection for BLE
        first_octet = int(mac.split(":")[0], 16)
        # BLE random MACs have the two least significant bits set
        return not (first_octet & 0xC0 == 0xC0)

    def _report(self, device, adv, rssi, classification, vulnerabilities, anomalies, rogue, is_mesh):
        url = self.options["discord_webhook_url"]
        if not url:
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        coord = self._get_gps_fix() if self.options["use_gpsd"] else None
        lat, lon, alt = ("N/A","N/A","N/A")
        src = "none"
        if coord:
            lat, lon, alt = coord[0], coord[1], coord[2] or "N/A"
            src = "gpsd"
        elif self.options["google_api_key"]:
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
            {"name":"Type","value":classification,"inline":True},
            {"name":"Mesh Network","value":str(is_mesh),"inline":True},
            {"name":"Vulnerabilities","value":", ".join(vulnerabilities),"inline":False},
            {"name":"Anomalies","value":", ".join(anomalies),"inline":False},
            {"name":"Rogue","value":rogue,"inline":True},
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
