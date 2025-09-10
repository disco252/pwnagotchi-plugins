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
    __version__ = "1.4"
    __license__ = "GPL3"
    __description__ = (
        "Bluetooth LE wardriving plugin with GPS, device classification, dynamic IEEE OUI lookup, security, anomaly, and mesh network detection."
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
        "oui_update_url": "https://standards-oui.ieee.org/oui/oui.txt",
        "auto_update_oui": True,
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.loop = None
        self.stop_event = threading.Event()
        self.gps_session = None
        self.last_fix = None
        self.oui_db = self._load_or_update_oui_db()

    def _download_oui_db(self):
        """Download the latest IEEE OUI database"""
        try:
            url = self.options["oui_update_url"]
            db_path = self.options["oui_db_path"]
            logging.info(f"[BLEWardrive] Downloading OUI database from {url}")
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            with open(db_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            logging.info(f"[BLEWardrive] OUI database downloaded to {db_path}")
            return True
        except Exception as e:
            logging.error(f"[BLEWardrive] Failed to download OUI database: {e}")
            return False

    def _load_or_update_oui_db(self):
        """Load OUI database, downloading if needed or requested"""
        db_path = self.options["oui_db_path"]
        
        # Check if we need to download
        if self.options.get("auto_update_oui", True):
            if not os.path.exists(db_path):
                logging.info("[BLEWardrive] OUI database not found, downloading...")
                self._download_oui_db()
            else:
                # Check age - update if older than 30 days
                try:
                    age = time.time() - os.path.getmtime(db_path)
                    if age > (30 * 24 * 3600):  # 30 days
                        logging.info("[BLEWardrive] OUI database is old, updating...")
                        self._download_oui_db()
                except OSError:
                    pass
        
        return self._parse_ieee_oui_db(db_path)

    def _parse_ieee_oui_db(self, db_path):
        """Parse the IEEE OUI database format"""
        oui_dict = {}
        if not os.path.exists(db_path):
            logging.warning(f"[BLEWardrive] OUI database file not found: {db_path}")
            return oui_dict
        
        try:
            with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
                current_oui = None
                
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines and headers
                    if not line or line.startswith('OUI/MA-L') or line.startswith('company_id'):
                        continue
                    
                    # Look for hex OUI lines like "28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd."
                    if '(hex)' in line and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            oui_part = parts[0].strip()
                            vendor_part = parts[-1].strip()
                            
                            # Extract OUI (first part before "(hex)")
                            if '(hex)' in oui_part:
                                oui = oui_part.split('(hex)')[0].strip()
                                oui = oui.replace('-', '').replace(':', '').upper()
                                if len(oui) >= 6:
                                    oui_dict[oui[:6]] = vendor_part
                    
                    # Also look for base 16 lines like "286FB9     (base 16)		Nokia Shanghai Bell Co., Ltd."
                    elif '(base 16)' in line and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            oui_part = parts[0].strip()
                            vendor_part = parts[-1].strip()
                            
                            # Extract OUI (first part before "(base 16)")
                            if '(base 16)' in oui_part:
                                oui = oui_part.split('(base 16)')[0].strip()
                                oui = oui.replace('-', '').replace(':', '').upper()
                                if len(oui) >= 6:
                                    oui_dict[oui[:6]] = vendor_part
                                    
        except Exception as e:
            logging.error(f"[BLEWardrive] Error parsing OUI database: {e}")
        
        logging.info(f"[BLEWardrive] Loaded {len(oui_dict)} OUIs from IEEE database")
        return oui_dict

    def _lookup_oui_vendor(self, mac_addr):
        """Look up vendor for a given MAC address"""
        oui = mac_addr.replace(":", "").replace("-", "").upper()[:6]
        return self.oui_db.get(oui, "Unknown")

    def on_loaded(self):
        for k, v in self.__defaults__.items():
            self.options.setdefault(k, v)
        if self.options["use_gpsd"] and HAS_GPSD:
            self._connect_gpsd()
        logging.info("[BLEWardrive] Loaded; GPSd=%s", bool(self.gps_session))
        threading.Thread(target=self._ble_loop, daemon=True).start()

    def _connect_gpsd(self):
        try:
            self.gps_session = gps.gps()
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
            mesh_devices = self._detect_mesh_networks(devices)
            for _, (device, adv) in devices.items():
                rssi = getattr(adv, "rssi", None) or getattr(device, "rssi", None)
                if rssi is not None:
                    classification = self._classify_device(device, adv)
                    vulnerabilities = self._detect_vulnerabilities(device, adv)
                    anomalies = self._detect_anomalies(device, adv)
                    vendor = self._lookup_oui_vendor(device.address)
                    rogue = self._detect_rogue_device(device, vendor)
                    is_mesh = device in mesh_devices
                    self._report(device, adv, rssi, classification, vendor, vulnerabilities, anomalies, rogue, is_mesh)
            await asyncio.sleep(interval)

    def _classify_device(self, device, adv):
        mfg = adv.manufacturer_data or {}
        if 0x004C in mfg:
            return "Apple Device"
        elif 0x00E0 in mfg:
            return "Android/Google Device"
        elif device.name:
            ln = device.name.lower()
            if "fitbit" in ln: return "Fitness Tracker"
            elif "temp" in ln or "sensor" in ln: return "IoT Sensor"
        return "Unknown"

    def _detect_mesh_networks(self, devices):
        mesh_uuids = {"00001827-0000-1000-8000-00805f9b34fb", "00001828-0000-1000-8000-00805f9b34fb"}
        mesh_devices = []
        for _, (device, adv) in devices.items():
            service_uuids = set(adv.service_uuids or [])
            if service_uuids.intersection(mesh_uuids):
                mesh_devices.append(device)
        return mesh_devices

    def _detect_vulnerabilities(self, device, adv):
        vulns = []
        if adv.service_uuids and "00001800-0000-1000-8000-00805f9b34fb" in adv.service_uuids:
            vulns.append("Exposed Generic Access Service")
        if self._is_static_mac(device.address):
            vulns.append("Static MAC Address (trackable)")
        if device.name and any(x in device.name.lower() for x in ("default", "test", "demo")):
            vulns.append("Weak Device Name")
        return vulns or ["None"]

    def _detect_anomalies(self, device, adv):
        alerts = []
        interval = getattr(adv, "interval", None)
        if interval is not None and interval < 20:
            alerts.append("Unusually short advertising interval")
        mfg = adv.manufacturer_data or {}
        for v in mfg.values():
            if len(v) > 32:
                alerts.append("Abnormally large manufacturer data")
        return alerts or ["None"]

    def _detect_rogue_device(self, device, vendor):
        rogue_vendors = {
            "Espressif Inc.", "Tuya", "Shenzhen", "Ubiquiti", "ALFA", "Raspberry Pi Foundation",
            "Generic", "Unknown", "Xiaomi", "Yeelink", "TP-LINK", "Test", "Demo", "Fake",
            # Add more based on the actual vendor names from IEEE database
            "Private", "IEEE Registration Authority"
        }
        # Check if vendor contains any rogue keywords
        vendor_lower = vendor.lower()
        for rogue in rogue_vendors:
            if rogue.lower() in vendor_lower:
                return f"YES ({vendor})"
        return f"NO ({vendor})"

    def _is_static_mac(self, mac):
        first_octet = int(mac.split(":")[0], 16)
        return not (first_octet & 0xC0 == 0xC0)

    def _report(self, device, adv, rssi, classification, vendor, vulnerabilities, anomalies, rogue, is_mesh):
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
        fields = [
            {"name":"Address","value":device.address,"inline":True},
            {"name":"Vendor","value":vendor,"inline":True},
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
