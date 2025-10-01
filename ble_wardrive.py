import os
import time
import threading
import logging
import requests
import asyncio
import json
import pwnagotchi.plugins as plugins
from bleak import BleakScanner

try:
    import gps
    HAS_GPSD = True
except ImportError:
    HAS_GPSD = False

class BLEWardrive(plugins.Plugin):
    __author__ = "disco252"
    __version__ = "1.6"
    __license__ = "GPL3"
    __description__ = (
        "Bluetooth LE wardriving plugin with GPS, device classification, IEEE OUI lookup, "
        "Bluetooth Company ID database, security, anomaly, and mesh network detection."
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
        "bluetooth_company_db_path": "/usr/local/share/pwnagotchi/bluetooth_company_ids.json",
        "auto_download_databases": True,
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.loop = None
        self.stop_event = threading.Event()
        self.gps_session = None
        self.last_fix = None
        self.oui_db = {}
        self.bluetooth_company_db = {}

    def _load_oui_db(self, db_path):
        """Load IEEE OUI database"""
        oui_dict = {}
        if not os.path.exists(db_path):
            logging.warning(f"[BLEWardrive] OUI database file not found: {db_path}")
            return oui_dict
            
        try:
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
        except Exception as e:
            logging.error(f"[BLEWardrive] Error loading OUI database: {e}")
            
        return oui_dict

    def _load_bluetooth_company_db(self, db_path):
        """Load Bluetooth Company Identifier database"""
        company_dict = {}
        if not os.path.exists(db_path):
            logging.warning(f"[BLEWardrive] Bluetooth Company ID database not found: {db_path}")
            return company_dict
        
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Handle Nordic's JSON format
            if isinstance(data, dict) and 'company_identifiers' in data:
                for entry in data['company_identifiers']:
                    company_dict[entry['code']] = entry['name']
            elif isinstance(data, list):
                # Handle list format
                for entry in data:
                    if isinstance(entry, dict) and 'code' in entry and 'name' in entry:
                        company_dict[entry['code']] = entry['name']
            else:
                # Handle simple dict format
                for code, name in data.items():
                    company_dict[int(code)] = name
            
            logging.info(f"[BLEWardrive] Loaded {len(company_dict)} Bluetooth Company IDs")
            
        except Exception as e:
            logging.error(f"[BLEWardrive] Error loading Bluetooth Company ID database: {e}")
        
        return company_dict

    def _download_bluetooth_company_db(self):
        """Download Bluetooth Company ID database from Nordic Semiconductor"""
        db_path = self.options["bluetooth_company_db_path"]
        
        try:
            # Use Nordic's maintained database
            url = "https://raw.githubusercontent.com/NordicSemiconductor/bluetooth-numbers-database/master/v1/company_identifiers.json"
            
            logging.info("[BLEWardrive] Downloading Bluetooth Company ID database...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            with open(db_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
                
            logging.info(f"[BLEWardrive] Downloaded Bluetooth Company ID database to {db_path}")
            return True
            
        except Exception as e:
            logging.error(f"[BLEWardrive] Failed to download Bluetooth Company ID database: {e}")
            return False

    def _lookup_oui_vendor(self, mac_addr):
        """Lookup MAC address vendor from IEEE OUI database"""
        if not mac_addr:
            return "Unknown"
        oui = mac_addr.replace(":", "").replace("-", "").upper()[:6]
        return self.oui_db.get(oui, "Unknown")

    def _lookup_bluetooth_vendor(self, manufacturer_data):
        """Extract and lookup Bluetooth company from manufacturer data"""
        if not manufacturer_data or len(manufacturer_data) < 2:
            return "Unknown", None
        
        try:
            # Extract company ID (little-endian, first 2 bytes)
            company_id = int.from_bytes(manufacturer_data[:2], 'little')
            company_name = self.bluetooth_company_db.get(company_id, f"Unknown (0x{company_id:04X})")
            proprietary_data = manufacturer_data[2:] if len(manufacturer_data) > 2 else None
            return company_name, proprietary_data
        except Exception as e:
            logging.debug(f"[BLEWardrive] Error parsing manufacturer data: {e}")
            return "Unknown", None

    def _format_manufacturer_data(self, manufacturer_data_dict):
        """Format manufacturer data with company name translation"""
        if not manufacturer_data_dict:
            return "None"
        
        formatted_entries = []
        for company_id, data in manufacturer_data_dict.items():
            # Get company name from our database
            company_name = self.bluetooth_company_db.get(company_id, f"Unknown (0x{company_id:04X})")
            
            # Format the data
            if isinstance(data, (bytes, bytearray)):
                data_hex = data.hex().upper()
                # Show first few bytes for readability
                if len(data_hex) > 16:
                    data_display = f"{data_hex[:16]}... ({len(data)} bytes)"
                else:
                    data_display = data_hex
            else:
                data_display = str(data)
            
            formatted_entries.append(f"{company_name}: {data_display}")
        
        return "; ".join(formatted_entries)

    def on_loaded(self):
        """Plugin initialization"""
        for k, v in self.__defaults__.items():
            self.options.setdefault(k, v)
            
        # Load IEEE OUI database
        self.oui_db = self._load_oui_db(self.options["oui_db_path"])
        
        # Load or download Bluetooth Company ID database
        bluetooth_db_path = self.options["bluetooth_company_db_path"]
        if not os.path.exists(bluetooth_db_path) and self.options.get("auto_download_databases", True):
            self._download_bluetooth_company_db()
        
        self.bluetooth_company_db = self._load_bluetooth_company_db(bluetooth_db_path)
        
        # Connect to GPSd if enabled
        if self.options["use_gpsd"] and HAS_GPSD:
            self._connect_gpsd()
            
        logging.info(f"[BLEWardrive] Loaded; GPSd={bool(self.gps_session)}; "
                    f"OUIs={len(self.oui_db)}; BT Companies={len(self.bluetooth_company_db)}")
        
        # Start BLE scanning thread
        threading.Thread(target=self._ble_loop, daemon=True).start()

    def _connect_gpsd(self):
        """Connect to GPS daemon"""
        try:
            self.gps_session = gps.gps()
            self.gps_session.stream(gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)
            logging.info("[BLEWardrive] Connected to gpsd")
        except Exception as e:
            self.gps_session = None
            logging.warning(f"[BLEWardrive] gpsd connection failed: {e}")

    def _get_gps_fix(self, attempts=5):
        """Get GPS coordinates with limited attempts"""
        if not self.gps_session:
            return None
            
        try:
            for _ in range(attempts):
                report = self.gps_session.next()
                if (report.get("class") == "TPV" and 
                    hasattr(report, "lat") and hasattr(report, "lon") and
                    getattr(report, "mode", 1) >= 2):
                    fix = (float(report.lat), float(report.lon), getattr(report, "alt", None))
                    self.last_fix = fix
                    return fix
        except Exception as e:
            logging.debug(f"[BLEWardrive] GPS error: {e}")
            
        return self.last_fix

    def _ble_loop(self):
        """Main BLE scanning loop"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.create_task(self._scan_loop())
        self.loop.run_forever()

    async def _scan_loop(self):
        """Async BLE scanning loop"""
        interval = self.options["scan_interval"]
        duration = self.options["scan_duration"]
        mesh_uuids = {"00001827-0000-1000-8000-00805f9b34fb", "00001828-0000-1000-8000-00805f9b34fb"}
        
        while not self.stop_event.is_set():
            try:
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
                    
                    self._report(device, adv, rssi, classification, vendor, 
                               vulnerabilities, anomalies, rogue, is_mesh)
                               
            except Exception as e:
                logging.error(f"[BLEWardrive] Scan error: {e}")
                
            await asyncio.sleep(interval)

    def _classify_device(self, device, adv):
        """Enhanced device classification using company database"""
        mfg = adv.manufacturer_data or {}
        
        # Check manufacturer data for better classification
        for company_id, data in mfg.items():
            company_name = self.bluetooth_company_db.get(company_id, "").lower()
            
            if company_id == 0x004C or "apple" in company_name:
                return "Apple Device"
            elif company_id == 0x00E0 or "google" in company_name:
                return "Android/Google Device"
            elif company_id == 0x0075 or "samsung" in company_name:
                return "Samsung Device"
            elif company_id == 0x0006 or "microsoft" in company_name:
                return "Microsoft Device"
            elif "fitbit" in company_name:
                return "Fitness Tracker"
            elif any(x in company_name for x in ["nordic", "espressif", "texas instruments"]):
                return "Development Board/Chip"
        
        # Fallback to name-based classification
        if device.name:
            ln = device.name.lower()
            if "fitbit" in ln:
                return "Fitness Tracker"
            elif any(x in ln for x in ["temp", "sensor", "humidity", "pressure"]):
                return "IoT Sensor"
            elif any(x in ln for x in ["speaker", "headphone", "earphone", "buds"]):
                return "Audio Device"
            elif any(x in ln for x in ["watch", "band", "tracker"]):
                return "Wearable Device"
                
        return "Unknown Device"

    def _detect_vulnerabilities(self, device, adv):
        """Detect potential security vulnerabilities"""
        vulns = []
        
        # Check for exposed services
        if adv.service_uuids and "00001800-0000-1000-8000-00805f9b34fb" in adv.service_uuids:
            vulns.append("Exposed Generic Access Service")
            
        # Check MAC address privacy
        first_octet = int(device.address.split(":")[0], 16)
        if not (first_octet & 0xC0 == 0xC0):  # Not random/private
            vulns.append("Static MAC Address (trackable)")
            
        # Check for weak device names
        if device.name and any(x in device.name.lower() for x in ("default", "test", "demo", "admin")):
            vulns.append("Weak Device Name")
            
        # Check for excessive advertising interval (battery drain attack potential)
        interval = getattr(adv, "interval", None)
        if interval is not None and interval < 20:
            vulns.append("Very short advertising interval")
            
        return vulns or ["None"]

    def _detect_anomalies(self, device, adv):
        """Detect unusual behavior patterns"""
        alerts = []
        
        # Check advertising interval
        interval = getattr(adv, "interval", None)
        if interval is not None and interval < 20:
            alerts.append("Unusually short advertising interval")
            
        # Check manufacturer data size
        for company_id, data in (adv.manufacturer_data or {}).items():
            if len(data) > 32:
                alerts.append(f"Large manufacturer data from {self.bluetooth_company_db.get(company_id, 'Unknown')}")
                
        # Check for multiple manufacturer data entries (unusual)
        if len(adv.manufacturer_data or {}) > 2:
            alerts.append("Multiple manufacturer data entries")
            
        return alerts or ["None"]

    def _detect_rogue_device(self, vendor):
        """Enhanced rogue device detection"""
        rogue_keywords = [
            "Espressif", "Tuya", "Shenzhen", "Ubiquiti", "ALFA", "Raspberry",
            "Generic", "Unknown", "Xiaomi", "Yeelink", "TP-LINK", "Test", 
            "Demo", "Private", "Development", "Nordic Semiconductor"
        ]
        v = vendor.lower()
        return "YES" if any(k.lower() in v for k in rogue_keywords) else "NO"

    def _report(self, device, adv, rssi, classification, vendor,
                vulnerabilities, anomalies, rogue, is_mesh):
        """Send enhanced device report to Discord"""
        url = self.options["discord_webhook_url"]
        if not url:
            logging.warning("[BLEWardrive] No Discord webhook URL configured")
            return

        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        coord = self._get_gps_fix() if self.options["use_gpsd"] else None
        lat, lon, alt, src = "N/A", "N/A", "N/A", "none"
        
        if coord:
            lat, lon, alt = coord
            src = "gpsd"
        elif self.options["google_api_key"]:
            try:
                res = requests.post(
                    "https://www.googleapis.com/geolocation/v1/geolocate",
                    params={"key": self.options["google_api_key"]},
                    json={"considerIp": True}, timeout=5
                ).json()
                loc = res.get("location", {})
                lat, lon = loc.get("lat","N/A"), loc.get("lng","N/A")
                src = "google"
            except Exception:
                pass

        # Format manufacturer data with company names
        manufacturer_display = self._format_manufacturer_data(adv.manufacturer_data)

        embed = {
            "title": ":satellite: BLE Device Detected",
            "fields": [
                {"name":"Address",          "value":device.address,                         "inline":True},
                {"name":"Vendor",           "value":vendor,                                  "inline":True},
                {"name":"Name",             "value":device.name or "<Unknown>",              "inline":True},
                {"name":"RSSI",             "value":f"{rssi} dBm",                           "inline":True},
                {"name":"Type",             "value":classification,                          "inline":True},
                {"name":"Mesh Network",     "value":str(is_mesh),                            "inline":True},
                {"name":"Vulnerabilities",  "value":", ".join(vulnerabilities),              "inline":False},
                {"name":"Anomalies",        "value":", ".join(anomalies),                    "inline":False},
                {"name":"Rogue",            "value":rogue,                                   "inline":True},
                {"name":"Time",             "value":ts,                                      "inline":True},
                {"name":"Latitude",         "value":str(lat),                                "inline":True},
                {"name":"Longitude",        "value":str(lon),                                "inline":True},
                {"name":"Altitude",         "value":str(alt),                                "inline":True},
                {"name":"Location Source",  "value":src,                                      "inline":True},
                {"name":"Manufacturer Data", "value":manufacturer_display,                   "inline":False},
            ],
            "color": 0x00ff00 if rogue == "NO" else 0xff6600,  # Green for clean, orange for rogue
            "footer": {"text":f"ble_wardrive v{self.__version__} | OUIs: {len(self.oui_db)} | BT Companies: {len(self.bluetooth_company_db)}"}
        }

        payload = {"embeds":[embed]}

        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code not in (200,204):
                logging.error(f"[BLEWardrive] Discord webhook error {resp.status_code}: {resp.text}")
            else:
                logging.info(f"[BLEWardrive] Reported device: {device.address} ({classification})")
        except Exception as e:
            logging.error(f"[BLEWardrive] Webhook exception: {e}")

    def on_unload(self, ui):
        """Plugin cleanup"""
        self.stop_event.set()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.gps_session:
            try:
                self.gps_session.close()
            except Exception:
                pass
        logging.info("[BLEWardrive] Plugin unloaded.")
