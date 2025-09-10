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
    __author__ = "disco252"
    __version__ = "1.4"
    __license__ = "GPL3"
    __description__ = (
        "Bluetooth LE wardriving plugin with GPS, device classification, IEEE OUI lookup, security, anomaly, and mesh detection."
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
                    vendor = parts[-1].strip()
                    if len(oui) >= 6:
                        oui_dict[oui[:6]] = vendor
        logging.info(f"[BLEWardrive] Loaded {len(oui_dict)} OUIs from IEEE database")
        return oui_dict

    def _lookup_oui_vendor(self, mac_addr):
        oui = mac_addr.replace(":", "").replace("-", "").upper()[:6]
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
        mesh_uuids = {"00001827-0000-1000-8000-00805f9b34fb", "00001828-0000-1000-8000-00805f9b34fb"}
        while not self.stop_event.is_set():
            devices = await BleakScanner.discover(timeout=duration, return_adv=True)
            for _, (device, adv) in devices.items():
                rssi = getattr(adv, "rssi", None) or getattr(device, "rssi", None)
                if rssi is None:
                    continue
                classification = self._classify_device(device, adv)
                vulnerabilities = self._detect_vulnerabilities(device, adv)
                anomalies = self._detect_anomalies(device, adv)
                vendor = self._lookup_oui_vendor(device.address)
                rogue = self._detect_rogue_device(vendor)
                is_mesh = bool(set(adv.service_uuids or []).intersection(mesh_uuids))
                self._report(device, adv, rssi, classification, vendor, vulnerabilities, anomalies, rogue, is_mesh)
            await asyncio.sleep(interval)

    def _classify_device(self, device, adv):
        mfg = adv.manufacturer_data or {}
        if 0x004C in mfg:
            return "Apple Device"
        if 0x00E0 in mfg:
            return "Android/Google Device"
        if device.name:
            ln = device.name.lower()
            if "fitbit" in ln:
                return "Fitness Tracker"
            if "temp" in ln or "sensor" in ln:
                return "IoT Sensor"
        return "Unknown"

    def _detect_vulnerabilities(self, device, adv):
        vulns = []
        if adv.service_uuids and "00001800-0000-1000-8000-00805f9b34fb" in adv.service_uuids:
            vulns.append("Exposed Generic Access Service")
        first_octet = int(device.address.split(":")[0], 16)
        if not (first_octet & 0xC0 == 0xC0):
            vulns.append("Static MAC Address (trackable)")
        if device.name and any(x in device.name.lower() for x in ("default", "test", "demo")):
            vulns.append("Weak Device Name")
        return vulns or ["None"]

    def _detect_anomalies(self, device, adv):
        alerts = []
        interval = getattr(adv, "interval", None)
        if interval is not None and interval < 20:
            alerts.append("Unusually short advertising interval")
        for v in (adv.manufacturer_data or {}).values():
            if len(v) > 32:
                alerts.append("Abnormally large manufacturer data")
        return alerts or ["None"]

    def _detect_rogue_device(self, vendor):
        rogue_keywords = [
            "Espressif", "Tuya", "Shenzhen", "Ubiquiti", "ALFA", "Raspberry",
            "Generic", "Unknown", "Xiaomi", "Yeelink", "TP-LINK", "Test", "Demo", "Private"
        ]
        v = vendor.lower()
        return "YES" if any(k.lower() in v for k in rogue_keywords) else "NO"

    def _report(self, device, adv, rssi, classification, vendor,
                vulnerabilities, anomalies, rogue, is_mesh):
        url = self.options["discord_webhook_url"]
        if not url:
            logging.warning("[BLEWardrive] No Discord webhook URL configured")
            return

        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        coord = self._get_gps_fix() if self.options["use_gpsd"] else None
        lat, lon = "N/A", "N/A"
        if coord:
            lat, lon = coord[0], coord[1]
        elif self.options["google_api_key"]:
            try:
                res = requests.post(
                    "https://www.googleapis.com/geolocation/v1/geolocate",
                    params={"key": self.options["google_api_key"]},
                    json={"considerIp": True}, timeout=5
                ).json()
                loc = res.get("location", {})
                lat, lon = loc.get("lat","N/A"), loc.get("lng","N/A")
            except Exception:
                pass

        message = (
            f"📡 **BLE Device Detected**\n"
            f"> **Address:** {device.address}\n"
            f"> **Vendor:** {vendor}\n"
            f"> **Name:** {device.name or '<Unknown>'}\n"
            f"> **RSSI:** {rssi} dBm\n"
            f"> **Type:** {classification}\n"
            f"> **Mesh:** {is_mesh}\n"
            f"> **Vulns:** {', '.join(vulnerabilities)}\n"
            f"> **Anomalies:** {', '.join(anomalies)}\n"
            f"> **Rogue:** {rogue}\n"
            f"> **Time:** {ts}\n"
            f"> **Lat/Lon:** {lat}, {lon}\n"
        )

        try:
            resp = requests.post(url, json={"content": message}, timeout=5)
            if resp.status_code not in (200, 204):
                logging.error(f"[BLEWardrive] Discord error {resp.status_code}: {resp.text}")
            else:
                logging.debug("[BLEWardrive] Message sent")
        except Exception as e:
            logging.error(f"[BLEWardrive] Webhook exception: {e}")

    def on_unload(self, ui):
        self.stop_event.set()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        logging.info("[BLEWardrive] Plugin unloaded.")
