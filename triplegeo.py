import logging
import requests
import os
import json
import time
import threading
import glob
import re
import pwnagotchi.plugins as plugins

def parse_config_directly():
    config = {}
    try:
        config_paths = [
            '/etc/pwnagotchi/config.toml',
            '/opt/pwnagotchi/config.toml',
            '/home/pi/pwnagotchi/config.toml',
            'config.toml'
        ]
        for path in config_paths:
            if os.path.exists(path):
                logging.info(f"[TripleGeo] Found config file: {path}")
                with open(path, 'r') as f:
                    content = f.read()
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('main.plugins.triplegeo.'):
                        try:
                            key_part = line.split('main.plugins.triplegeo.')[1]
                            if '=' in key_part:
                                key, value = key_part.split('=', 1)
                                key = key.strip()
                                value = value.strip()
                                if value.startswith('"') and value.endswith('"'):
                                    value = value[1:-1]
                                elif value.lower() == 'true':
                                    value = True
                                elif value.lower() == 'false':
                                    value = False
                                elif value.startswith('[') and value.endswith(']'):
                                    value = value[1:-1].replace('"', '').replace("'", "")
                                    value = [v.strip() for v in value.split(',') if v.strip()]
                                elif value.isdigit():
                                    value = int(value)
                                config[key] = value
                                logging.debug(f"[TripleGeo] Parsed config: {key} = {value}")
                        except Exception as e:
                            logging.warning(f"[TripleGeo] Error parsing line '{line}': {e}")
                break
    except Exception as e:
        logging.error(f"[TripleGeo] Error parsing config file: {e}")
    return config

try:
    import gps
    HAS_GPSD = True
except ImportError:
    HAS_GPSD = False

class TripleGeo(plugins.Plugin):
    __author__ = "disco252"
    __version__ = "1.8.2"
    __license__ = "GPL3"
    __description__ = (
        "Geolocation and Discord notifications for Pwnagotchi. "
        "Posts events to Discord using validated JSON webhook requests."
    )
    __name__ = "triplegeo"
    __defaults__ = {
        "enabled": False,
        "mode": ["gps", "google", "wigle"],
        "google_api_key": "",
        "wigle_user": "",
        "wigle_token": "",
        "handshake_dir": "/home/pi/handshakes",
        "processed_file": "/root/.triplegeo_processed",
        "pending_file": "/root/.triplegeo_pending",
        "wigle_delay": 2,
        "max_wigle_per_minute": 10,
        "wigle_upload": True,
        "global_log_file": "/root/triplegeo_globalaplog.jsonl",
        "discord_webhook_url": "",
        "oui_db_path": "/usr/local/share/pwnagotchi/ieee_oui.txt",
        "cache_expire_minutes": 30,
        "debug_logging": False,
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.api_mutex = threading.Lock()
        self.processed = set()
        self.pending = []
        self.gps_session = None
        self._gps_last = None
        self.oui_db = {}
        self.ap_cache = {}
        self.ap_cache_lock = threading.Lock()

    def _load_oui_db(self, db_path):
        oui_dict = {}
        if not os.path.exists(db_path):
            logging.warning(f"[TripleGeo] OUI database file not found: {db_path}")
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
        except Exception as e:
            logging.error(f"[TripleGeo] Error loading OUI database: {e}")
        logging.info(f"[TripleGeo] Loaded {len(oui_dict)} OUIs from database")
        return oui_dict

    def _lookup_oui_vendor(self, mac_addr):
        if not mac_addr:
            return "Unknown"
        oui = mac_addr.replace(":", "").replace("-", "").upper()[:6]
        return self.oui_db.get(oui, "Unknown")

    def test_network_connectivity(self):
        try:
            r = requests.get("https://discord.com", timeout=10)
            logging.info(f"[TripleGeo] Discord connectivity test: {r.status_code}")
            return r.status_code == 200
        except Exception as e:
            logging.error(f"[TripleGeo] Discord connectivity failed: {e}")
            return False

    def create_embed(self, event, title):
        def safe_str(value, maxlen=1024):
            if value is None or value == "N/A": return "N/A"
            sv = str(value)
            return sv[:maxlen]
        fields = [
            {"name": "SSID", "value": safe_str(event.get("ssid")), "inline": True},
            {"name": "BSSID", "value": safe_str(event.get("bssid")), "inline": True},
            {"name": "Client", "value": safe_str(event.get("client")), "inline": True},
            {"name": "Signal", "value": f"{safe_str(event.get('rssi'))} dBm", "inline": True},
            {"name": "SNR", "value": f"{safe_str(event.get('snr'))} dB", "inline": True},
            {"name": "Channel", "value": safe_str(event.get("channel")), "inline": True},
            {"name": "Frequency", "value": f"{safe_str(event.get('frequency'))} MHz", "inline": True},
            {"name": "Band", "value": safe_str(event.get("band")), "inline": True},
            {"name": "Encryption", "value": safe_str(event.get("encryption")), "inline": True},
            {"name": "Vendor", "value": safe_str(event.get("vendor")), "inline": True},
            {"name": "Timestamp", "value": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(event.get("timestamp", time.time()))), "inline": True},
            {"name": "Location", "value": f"{safe_str(event.get('lat'))},{safe_str(event.get('lon'))}", "inline": True},
        ]
        if event.get("handshake_file"):
            fields.append({"name": "File", "value": safe_str(os.path.basename(event["handshake_file"])), "inline": False})
        return {
            "title": safe_str(title, 256),
            "fields": fields[:25],
            "color": 0x406080,
            "footer": {"text": f"triplegeo v{self.__version__}"}
        }

    def on_loaded(self):
        logging.info("[TripleGeo] Loading plugin configuration...")
        config_loaded = False
        try:
            if hasattr(self, 'config') and self.config is not None:
                for key, default_val in self.__defaults__.items():
                    self.options[key] = self.config.get(key, default_val)
                config_loaded = True
        except Exception as e:
            logging.warning(f"[TripleGeo] config load failed: {e}")
        if not config_loaded:
            logging.info("[TripleGeo] Using direct config file parsing")
            parsed_config = parse_config_directly()
            if parsed_config:
                for key, default_val in self.__defaults__.items():
                    self.options[key] = parsed_config.get(key, default_val)
                config_loaded = True
            else:
                logging.warning("[TripleGeo] Direct config parsing failed")
        if not config_loaded:
            logging.warning("[TripleGeo] Using env and defaults")
            self.options = dict(self.__defaults__)
            env_webhook = os.environ.get('TRIPLEGEO_DISCORD_WEBHOOK_URL', '')
            env_enabled = os.environ.get('TRIPLEGEO_ENABLED', 'false').lower() == 'true'
            if env_webhook:
                self.options['discord_webhook_url'] = env_webhook
                self.options['enabled'] = True
            elif env_enabled:
                self.options['enabled'] = True

        # Full config debug output
        for k, v in self.options.items():
            logging.info(f"[TripleGeo] config: {k} = {v}")

        webhook_url = self.options.get('discord_webhook_url', '')
        if webhook_url and not self.options.get('enabled', False):
            logging.info("[TripleGeo] Auto-enabling plugin since webhook is set")
            self.options['enabled'] = True

        self.oui_db = self._load_oui_db(self.options["oui_db_path"])
        self._load_storage()
        self._connect_gpsd()
        if self.options.get("discord_webhook_url"):
            if self.test_network_connectivity():
                threading.Timer(10.0, self.test_discord_webhook).start()
            else:
                logging.warning("[TripleGeo] Discord unreachable")
        self._report_existing_coords()

    def test_discord_webhook(self):
        url = self.options.get('discord_webhook_url', '')
        if not url:
            logging.warning("[TripleGeo] No webhook URL for testing")
            return
        test_event = {
            "timestamp": time.time(),
            "ssid": "TestNet",
            "bssid": "00:11:22:33:44:55",
            "client": "TestClient",
            "rssi": -50,
            "snr": 35,
            "channel": 6,
            "frequency": 2437,
            "band": "2.4 GHz",
            "encryption": "WPA2",
            "vendor": "TestVendor",
            "lat": "0.0",
            "lon": "0.0",
            "handshake_file": "test.pcap"
        }
        self.send_discord_webhook(test_event, title="TripleGeo Test Message")

    def on_handshake(self, agent, filename, ap, client):
        if not self.options.get("enabled", False):
            logging.info("[TripleGeo] Plugin disabled, skipping handshake processing")
            return
        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        ssid, bssid = self._extract_info_from_filename(filename)
        ap_mac = None
        try:
            if hasattr(ap, 'mac') and ap.mac:
                ap_mac = ap.mac
            elif hasattr(ap, 'bssid') and ap.bssid:
                ap_mac = ap.bssid
            elif isinstance(ap, dict):
                ap_mac = ap.get('mac') or ap.get('bssid')
        except Exception as e:
            logging.warning(f"[TripleGeo] Error extracting MAC: {e}")
        if not ap_mac and bssid:
            ap_mac = bssid
        cached_ap = {}
        if ap_mac:
            try:
                with self.ap_cache_lock:
                    cached_ap = self.ap_cache.get(ap_mac, {})
            except Exception as e:
                logging.error(f"[TripleGeo] Cache access error: {e}")
        try:
            rssi = cached_ap.get('rssi') or getattr(ap, 'rssi', None) or "N/A"
            channel = cached_ap.get('channel') or getattr(ap, 'channel', None) or "N/A"
            encryption = cached_ap.get('encryption') or getattr(ap, 'encryption', None) or "N/A"
            frequency = cached_ap.get('frequency') or self._calculate_frequency(channel)
            band = cached_ap.get('band') or self._calculate_band(channel)
            vendor = cached_ap.get('vendor') or self._lookup_oui_vendor(ap_mac) if ap_mac else "Unknown"
        except Exception as e:
            logging.error(f"[TripleGeo] AP data extraction error: {e}")
            rssi = channel = encryption = frequency = "N/A"
            band = "unknown"
            vendor = "Unknown"
        snr = "N/A"
        try:
            noise = getattr(ap, "noise", None)
            if isinstance(rssi, (int, float)) and isinstance(noise, (int, float)):
                snr = rssi - noise
            elif isinstance(rssi, (int, float)) and rssi != 0:
                snr = rssi - (-95)
        except Exception as e:
            logging.warning(f"[TripleGeo] SNR error: {e}")
        if not gps_coord and cached_ap.get('gps_coord'):
            gps_coord = cached_ap['gps_coord']
        client_mac = ""
        try:
            if client and hasattr(client, 'mac'): client_mac = client.mac
            elif isinstance(client, dict): client_mac = client.get('mac', '')
        except Exception as e:
            logging.warning(f"[TripleGeo] Client MAC error: {e}")
        entry = {
            "timestamp": time.time(),
            "ssid": ssid,
            "bssid": ap_mac or "Unknown",
            "client": client_mac,
            "rssi": rssi,
            "snr": snr,
            "channel": channel,
            "frequency": frequency,
            "band": band,
            "encryption": encryption,
            "lat": gps_coord[0] if gps_coord else "N/A",
            "lon": gps_coord[1] if gps_coord else "N/A",
            "handshake_file": filename,
            "vendor": vendor
        }
        self.send_discord_webhook(entry, title="New Handshake Captured")

    def send_discord_webhook(self, event, title="New Event"):
        url = self.options.get("discord_webhook_url", "")
        if not url:
            logging.warning("[TripleGeo] No Discord webhook URL set")
            return
        try:
            embed = self.create_embed(event, title)
            payload = {"embeds": [embed]}
            r = requests.post(url, json=payload, timeout=15)
            logging.info(f"[TripleGeo] Discord response: {r.status_code}")
            if r.text:
                logging.info(f"[TripleGeo] Discord response text: {r.text}")
            if r.status_code == 204:
                logging.info("[TripleGeo] Discord webhook delivered")
                return True
            else:
                logging.error(f"[TripleGeo] Discord webhook failed: {r.status_code}")
                # Fallback to simple message
                simple_payload = {
                    "content": f"{title}\nSSID: {event.get('ssid','Unknown')}\nBSSID: {event.get('bssid','Unknown')}\nSignal: {event.get('rssi','N/A')} dBm\nChannel: {event.get('channel','N/A')}\nLocation: {event.get('lat','N/A')},{event.get('lon','N/A')}\nFile: {os.path.basename(event.get('handshake_file','unknown'))}"
                }
                test_r = requests.post(url, json=simple_payload, timeout=10)
                logging.info(f"[TripleGeo] Simple message result: {test_r.status_code} {test_r.text}")
                return test_r.status_code == 204
        except Exception as e:
            logging.error(f"[TripleGeo] Webhook send error: {e}")
        return False

    def _extract_info_from_filename(self, filename):
        shortname = os.path.basename(filename).replace(".pcap", "")
        parts = shortname.split("_")
        ssid = parts[0] if parts else shortname
        bssid = None
        for part in parts[1:]:
            if re.match(r'^[0-9a-fA-F]{12}$', part):
                bssid = ':'.join([part[i:i+2] for i in range(0, 12, 2)])
                break
            elif re.match(r'^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$', part):
                bssid = part
                break
        return ssid, bssid

    def _calculate_frequency(self, channel):
        try:
            ch = int(channel)
            if 1 <= ch <= 14:
                return 2412 + (ch - 1) * 5
            elif 36 <= ch <= 165:
                return 5000 + ch * 5
            elif 1 <= ch <= 233:
                return 5955 + (ch - 1) * 5
        except Exception:
            return "N/A"
        return "N/A"

    def _calculate_band(self, channel):
        try:
            ch = int(channel)
            if 1 <= ch <= 14: return "2.4 GHz"
            elif 36 <= ch <= 165: return "5 GHz"
            elif 1 <= ch <= 233: return "6 GHz"
        except Exception:
            return "unknown"
        return "unknown"

    def _load_storage(self):
        pf = self.options["processed_file"]
        self.processed = set()
        if os.path.exists(pf):
            try:
                with open(pf, 'r') as f:
                    self.processed = set(json.load(f))
                logging.debug(f"[TripleGeo] Loaded {len(self.processed)} processed entries")
            except Exception as e:
                logging.warning(f"[TripleGeo] Error loading processed file: {e}")
        pend = self.options["pending_file"]
        self.pending = []
        if os.path.exists(pend):
            try:
                with open(pend, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.pending = json.loads(content)
                logging.debug(f"[TripleGeo] Loaded {len(self.pending)} pending entries")
            except Exception as e:
                logging.warning(f"[TripleGeo] Error loading pending file: {e}")

    def _save_pending(self):
        try:
            with open(self.options["pending_file"], "w") as f:
                json.dump(self.pending, f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving pending: {e}")

    def _connect_gpsd(self):
        if not HAS_GPSD:
            logging.warning("[TripleGeo] gpsd module not found, GPS disabled.")
            return
        try:
            self.gps_session = gps.gps()
            self.gps_session.stream(gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)
            logging.info("[TripleGeo] Connected to gpsd")
        except Exception as e:
            self.gps_session = None
            logging.warning(f"[TripleGeo] gpsd connection failed: {e}")

    def get_gps_coord(self, max_attempts=10):
        if not self.gps_session:
            return self._gps_last
        try:
            for _ in range(max_attempts):
                report = self.gps_session.next()
                if (report.get('class') == 'TPV'
                        and getattr(report, 'mode', 1) >= 2
                        and hasattr(report, 'lat') and hasattr(report, 'lon')):
                    lat = float(report.lat)
                    lon = float(report.lon)
                    alt = getattr(report, 'alt', None)
                    self._gps_last = (lat, lon, float(alt)) if alt is not None else (lat, lon)
                    return self._gps_last
        except Exception as e:
            logging.warning(f"[TripleGeo] GPS exception: {e}")
        return self._gps_last

    def _report_existing_coords(self):
        webhook_url = self.options.get('discord_webhook_url', '')
        if not webhook_url:
            logging.info("[TripleGeo] No webhook for coord reporting")
            return
        hd = self.options.get("handshake_dir", "/home/pi/handshakes")
        patterns = [
            os.path.join(hd, "*.triplegeo.coord.json"),
            os.path.join(hd, "*.coord.json")
        ]
        files = []
        for pattern in patterns:
            try:
                files.extend(glob.glob(pattern))
            except Exception as e:
                logging.warning(f"[TripleGeo] Glob error: {e}")
        logging.info(f"[TripleGeo] Found {len(files)} existing coord.json files.")

    def on_unload(self, ui):
        try:
            self._save_pending()
            if hasattr(self, 'gps_session') and self.gps_session:
                self.gps_session.close()
            logging.info("[TripleGeo] Plugin cleanup completed")
        except Exception as e:
            logging.warning(f"[TripleGeo] Error during unload: {e}")
        logging.info("[TripleGeo] Plugin unloaded")
