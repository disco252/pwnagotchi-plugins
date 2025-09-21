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
        "Geolocation and Discord notifications for Pwnagotchi handshake captures. "
        "Posts detailed handshake events to Discord with signal data and GPS coordinates."
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
        self.handshake_count = 0

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

    def _cleanup_ap_cache(self):
        if not hasattr(self, 'ap_cache_lock'):
            return
        expire_time = time.time() - (self.options.get('cache_expire_minutes', 30) * 60)
        with self.ap_cache_lock:
            expired_keys = [
                mac for mac, data in self.ap_cache.items()
                if data.get('timestamp', 0) < expire_time
            ]
            for mac in expired_keys:
                del self.ap_cache[mac]
            if expired_keys and self.options.get('debug_logging', False):
                logging.debug(f"[TripleGeo] Cleaned up {len(expired_keys)} expired AP cache entries")

    def create_embed(self, event, title):
        def safe_str(value, maxlen=1024):
            if value is None or value == "N/A": 
                return "N/A"
            sv = str(value)
            return sv[:maxlen] if len(sv) > maxlen else sv
        
        # Build comprehensive field list
        fields = [
            {"name": "SSID", "value": safe_str(event.get("ssid", "Unknown")), "inline": True},
            {"name": "BSSID", "value": safe_str(event.get("bssid", "Unknown")), "inline": True},
            {"name": "Client", "value": safe_str(event.get("client", "None")), "inline": True},
            {"name": "Signal", "value": f"{safe_str(event.get('rssi', 'N/A'))} dBm", "inline": True},
            {"name": "SNR", "value": f"{safe_str(event.get('snr', 'N/A'))} dB", "inline": True},
            {"name": "Channel", "value": safe_str(event.get("channel", "N/A")), "inline": True},
            {"name": "Frequency", "value": f"{safe_str(event.get('frequency', 'N/A'))} MHz", "inline": True},
            {"name": "Band", "value": safe_str(event.get("band", "unknown")), "inline": True},
            {"name": "Encryption", "value": safe_str(event.get("encryption", "N/A")), "inline": True},
            {"name": "Vendor", "value": safe_str(event.get("vendor", "Unknown")), "inline": True},
        ]
        
        # Add timestamp
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(event.get("timestamp", time.time())))
        fields.append({"name": "Timestamp", "value": ts, "inline": True})
        
        # Add GPS location
        lat = event.get('lat', 'N/A')
        lon = event.get('lon', 'N/A')
        alt = event.get('altitude', 'N/A')
        location_text = f"Lat: {lat}, Lon: {lon}"
        if alt != 'N/A':
            location_text += f", Alt: {alt}m"
        fields.append({"name": "Location", "value": location_text, "inline": True})
        
        # Add filename
        if event.get("handshake_file"):
            filename = os.path.basename(event["handshake_file"])
            fields.append({"name": "File", "value": safe_str(filename), "inline": False})
        
        # Color based on GPS availability and signal strength
        color = 0x00ff00  # Green for GPS
        if lat == 'N/A' or lon == 'N/A':
            color = 0xff9900  # Orange for no GPS
        
        return {
            "title": safe_str(title, 256),
            "fields": fields[:25],  # Discord max 25 fields
            "color": color,
            "footer": {"text": f"triplegeo v{self.__version__} | Handshake #{self.handshake_count}"}
        }

    def on_loaded(self):
        logging.info("[TripleGeo] Loading TripleGeo plugin...")
        
        # Load configuration with fallbacks
        config_loaded = False
        try:
            if hasattr(self, 'config') and self.config is not None:
                for key, default_val in self.__defaults__.items():
                    self.options[key] = self.config.get(key, default_val)
                config_loaded = True
                logging.info("[TripleGeo] Config loaded via standard method")
        except Exception as e:
            logging.warning(f"[TripleGeo] Standard config load failed: {e}")
        
        if not config_loaded:
            logging.info("[TripleGeo] Using direct config file parsing")
            parsed_config = parse_config_directly()
            if parsed_config:
                for key, default_val in self.__defaults__.items():
                    self.options[key] = parsed_config.get(key, default_val)
                config_loaded = True
                logging.info(f"[TripleGeo] Loaded {len(parsed_config)} config values from file")
            else:
                logging.warning("[TripleGeo] Direct config parsing failed")
        
        if not config_loaded:
            logging.warning("[TripleGeo] Using environment variables and defaults")
            self.options = dict(self.__defaults__)
            env_webhook = os.environ.get('TRIPLEGEO_DISCORD_WEBHOOK_URL', '')
            env_enabled = os.environ.get('TRIPLEGEO_ENABLED', 'false').lower() == 'true'
            if env_webhook:
                self.options['discord_webhook_url'] = env_webhook
                self.options['enabled'] = True
                logging.info("[TripleGeo] Using webhook from environment variable")
            elif env_enabled:
                self.options['enabled'] = True

        # Log configuration
        webhook_url = self.options.get('discord_webhook_url', '')
        if webhook_url and not self.options.get('enabled', False):
            logging.info("[TripleGeo] Auto-enabling plugin since webhook is configured")
            self.options['enabled'] = True

        logging.info(f"[TripleGeo] Plugin enabled: {self.options.get('enabled', False)}")
        logging.info(f"[TripleGeo] Discord webhook: {'Yes' if webhook_url else 'No'}")
        if webhook_url:
            logging.info(f"[TripleGeo] Webhook URL: {webhook_url[:50]}...")

        # Initialize components
        self.oui_db = self._load_oui_db(self.options["oui_db_path"])
        self._load_storage()
        self._connect_gpsd()
        
        logging.info(f"[TripleGeo] TripleGeo plugin loaded successfully")

    def on_unfiltered_ap_list(self, agent, data):
        """Cache AP data for correlation with handshakes - CRITICAL METHOD"""
        if not self.options.get("enabled", False):
            return

        if not isinstance(data, dict) or 'wifi' not in data or 'aps' not in data['wifi']:
            return

        # Get GPS coordinates once for this scan
        gps_coord = None
        if HAS_GPSD and self.gps_session:
            try:
                gps_coord = self.get_gps_coord(max_attempts=3)  # Quick GPS check
            except Exception as e:
                logging.debug(f"[TripleGeo] GPS read error: {e}")

        now = time.time()

        # Periodic cache cleanup
        if now % 300 < 1:  # Every ~5 minutes
            self._cleanup_ap_cache()

        cached_count = 0
        with self.ap_cache_lock:
            for ap in data['wifi']['aps']:
                ap_mac = ap.get('mac', '')
                if not ap_mac:
                    continue

                # Cache comprehensive AP data
                self.ap_cache[ap_mac] = {
                    'ssid': ap.get('hostname', 'Hidden'),
                    'rssi': ap.get('rssi', 'N/A'),
                    'channel': ap.get('channel', 'N/A'),
                    'encryption': ap.get('encryption', 'N/A'),
                    'frequency': self._calculate_frequency(ap.get('channel', 'N/A')),
                    'band': self._calculate_band(ap.get('channel', 'N/A')),
                    'vendor': self._lookup_oui_vendor(ap_mac),
                    'timestamp': now,
                    'gps_coord': gps_coord
                }
                cached_count += 1

        if self.options.get('debug_logging', False) and cached_count > 0:
            logging.debug(f"[TripleGeo] Cached {cached_count} APs, total: {len(self.ap_cache)}")

    def on_handshake(self, agent, filename, ap, client):
        """Process handshake captures and send to Discord"""
        if not self.options.get("enabled", False):
            logging.info("[TripleGeo] Plugin disabled, skipping handshake")
            return

        self.handshake_count += 1
        logging.info(f"[TripleGeo] Processing handshake #{self.handshake_count}: {os.path.basename(filename)}")

        # Get current GPS coordinates (non-blocking)
        gps_coord = None
        if HAS_GPSD and self.gps_session:
            try:
                gps_coord = self.get_gps_coord(max_attempts=2)
            except Exception as e:
                logging.debug(f"[TripleGeo] GPS error during handshake: {e}")

        # Extract SSID and BSSID from filename
        ssid, bssid = self._extract_info_from_filename(filename)

        # Get AP MAC from multiple sources
        ap_mac = None
        try:
            if hasattr(ap, 'mac') and ap.mac:
                ap_mac = ap.mac
            elif hasattr(ap, 'bssid') and ap.bssid:
                ap_mac = ap.bssid
            elif isinstance(ap, dict):
                ap_mac = ap.get('mac') or ap.get('bssid')
        except Exception as e:
            logging.warning(f"[TripleGeo] Error extracting AP MAC: {e}")

        # Fallback to filename extraction
        if not ap_mac and bssid:
            ap_mac = bssid

        logging.info(f"[TripleGeo] Handshake - SSID: {ssid}, BSSID: {ap_mac}")

        # Look up cached AP data
        cached_ap = {}
        if ap_mac:
            try:
                with self.ap_cache_lock:
                    cached_ap = self.ap_cache.get(ap_mac, {})
                    if cached_ap:
                        logging.info(f"[TripleGeo] Found cached data for {ap_mac}")
                    else:
                        logging.info(f"[TripleGeo] No cached data for {ap_mac}")
            except Exception as e:
                logging.error(f"[TripleGeo] Cache access error: {e}")

        # Extract technical data with fallbacks
        try:
            rssi = cached_ap.get('rssi') or getattr(ap, 'rssi', None) or "N/A"
            channel = cached_ap.get('channel') or getattr(ap, 'channel', None) or "N/A"
            encryption = cached_ap.get('encryption') or getattr(ap, 'encryption', None) or "N/A"
            frequency = cached_ap.get('frequency') or self._calculate_frequency(channel)
            band = cached_ap.get('band') or self._calculate_band(channel)
            vendor = cached_ap.get('vendor') or (self._lookup_oui_vendor(ap_mac) if ap_mac else "Unknown")
        except Exception as e:
            logging.error(f"[TripleGeo] Data extraction error: {e}")
            rssi = channel = encryption = frequency = "N/A"
            band = "unknown"
            vendor = "Unknown"

        # Calculate SNR
        snr = "N/A"
        try:
            noise = getattr(ap, "noise", None)
            if isinstance(rssi, (int, float)) and isinstance(noise, (int, float)):
                snr = rssi - noise
            elif isinstance(rssi, (int, float)) and rssi != 0:
                snr = rssi - (-95)  # Estimated noise floor
        except Exception as e:
            logging.debug(f"[TripleGeo] SNR calculation error: {e}")

        # Use cached GPS if current unavailable
        if not gps_coord and cached_ap.get('gps_coord'):
            gps_coord = cached_ap['gps_coord']
            logging.info("[TripleGeo] Using cached GPS coordinates")

        # Get client MAC
        client_mac = ""
        try:
            if client and hasattr(client, 'mac'):
                client_mac = client.mac
            elif isinstance(client, dict):
                client_mac = client.get('mac', '')
        except Exception as e:
            logging.debug(f"[TripleGeo] Client MAC extraction error: {e}")

        # Build event data
        entry = {
            "timestamp": time.time(),
            "ssid": ssid,
            "bssid": ap_mac or "Unknown",
            "client": client_mac or "None",
            "rssi": rssi,
            "snr": snr,
            "channel": channel,
            "frequency": frequency,
            "band": band,
            "encryption": encryption,
            "lat": gps_coord[0] if gps_coord else "N/A",
            "lon": gps_coord[1] if gps_coord else "N/A",
            "altitude": gps_coord[2] if gps_coord and len(gps_coord) > 2 else "N/A",
            "source": "gpsd" if gps_coord else "none",
            "handshake_file": filename,
            "vendor": vendor
        }

        # Log technical details
        logging.info(f"[TripleGeo] Technical data - RSSI: {rssi}, Channel: {channel}, Band: {band}, Encryption: {encryption}")

        # Save GPS coordinates to file if available
        if gps_coord:
            coord_file = filename.replace(".pcap", ".triplegeo.coord.json")
            coord_data = {
                "coord": {"lat": gps_coord[0], "lon": gps_coord[1]},
                "source": "gpsd"
            }
            if len(gps_coord) > 2:
                coord_data["coord"]["altitude"] = gps_coord[2]
            try:
                with open(coord_file, "w") as f:
                    json.dump(coord_data, f)
                logging.info(f"[TripleGeo] Saved coordinates to {os.path.basename(coord_file)}")
            except Exception as e:
                logging.warning(f"[TripleGeo] Could not save coord file: {e}")

        # Save to pending list
        try:
            if filename not in self.pending:
                self.pending.append(filename)
                self._save_pending()
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving pending: {e}")

        # Send to Discord
        logging.info(f"[TripleGeo] Sending handshake to Discord: {ssid}")
        success = self.send_discord_webhook(entry, title="New Handshake Captured")
        
        if success:
            logging.info(f"[TripleGeo] Successfully sent handshake #{self.handshake_count} to Discord")
        else:
            logging.error(f"[TripleGeo] Failed to send handshake #{self.handshake_count} to Discord")

    def send_discord_webhook(self, event, title="New Handshake"):
        """Send handshake data to Discord webhook"""
        url = self.options.get("discord_webhook_url", "")
        if not url:
            logging.warning("[TripleGeo] No Discord webhook URL configured")
            return False

        try:
            # Create embed
            embed = self.create_embed(event, title)
            payload = {"embeds": [embed]}

            # Send request
            logging.info("[TripleGeo] Sending Discord webhook...")
            r = requests.post(url, json=payload, timeout=15)
            
            logging.info(f"[TripleGeo] Discord response: {r.status_code}")
            if r.text:
                logging.info(f"[TripleGeo] Discord response text: {r.text}")

            # Check for success (204 or 200)
            if r.status_code in [200, 204]:
                logging.info("[TripleGeo] Discord webhook delivered successfully")
                return True
            else:
                logging.error(f"[TripleGeo] Discord webhook failed: {r.status_code}")
                
                # Try fallback simple message
                logging.info("[TripleGeo] Attempting simple message fallback...")
                simple_payload = {
                    "content": f"**{title}**\n"
                              f"SSID: {event.get('ssid','Unknown')}\n"
                              f"BSSID: {event.get('bssid','Unknown')}\n"
                              f"Signal: {event.get('rssi','N/A')} dBm\n"
                              f"Channel: {event.get('channel','N/A')}\n"
                              f"Encryption: {event.get('encryption','N/A')}\n"
                              f"Location: {event.get('lat','N/A')},{event.get('lon','N/A')}\n"
                              f"File: {os.path.basename(event.get('handshake_file','unknown'))}"
                }
                
                fallback_r = requests.post(url, json=simple_payload, timeout=10)
                logging.info(f"[TripleGeo] Fallback result: {fallback_r.status_code}")
                return fallback_r.status_code in [200, 204]

        except Exception as e:
            logging.error(f"[TripleGeo] Discord webhook error: {e}")
            return False

    def _extract_info_from_filename(self, filename):
        """Extract SSID and BSSID from handshake filename"""
        shortname = os.path.basename(filename).replace(".pcap", "")
        parts = shortname.split("_")
        ssid = parts[0] if parts else shortname
        bssid = None
        
        # Look for MAC pattern in filename parts
        for part in parts[1:]:
            if re.match(r'^[0-9a-fA-F]{12}$', part):  # 12 hex chars
                bssid = ':'.join([part[i:i+2] for i in range(0, 12, 2)])
                break
            elif re.match(r'^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$', part):  # Formatted MAC
                bssid = part
                break
        
        return ssid, bssid

    def _calculate_frequency(self, channel):
        """Calculate frequency from channel number"""
        try:
            ch = int(channel)
            if 1 <= ch <= 14:
                return 2412 + (ch - 1) * 5
            elif 36 <= ch <= 165:
                return 5000 + ch * 5
            elif 1 <= ch <= 233:  # 6 GHz
                return 5955 + (ch - 1) * 5
        except (ValueError, TypeError):
            pass
        return "N/A"

    def _calculate_band(self, channel):
        """Calculate band from channel number"""
        try:
            ch = int(channel)
            if 1 <= ch <= 14:
                return "2.4 GHz"
            elif 36 <= ch <= 165:
                return "5 GHz"
            elif 1 <= ch <= 233:
                return "6 GHz"
        except (ValueError, TypeError):
            pass
        return "unknown"

    def _load_storage(self):
        """Load processed handshakes and pending files"""
        # Load processed handshakes
        pf = self.options["processed_file"]
        self.processed = set()
        if os.path.exists(pf):
            try:
                with open(pf, 'r') as f:
                    self.processed = set(json.load(f))
                logging.debug(f"[TripleGeo] Loaded {len(self.processed)} processed entries")
            except Exception as e:
                logging.warning(f"[TripleGeo] Error loading processed file: {e}")

        # Load pending handshakes
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

    def _save_processed(self):
        """Save processed entries to file"""
        try:
            with open(self.options["processed_file"], "w") as f:
                json.dump(list(self.processed), f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving processed file: {e}")

    def _save_pending(self):
        """Save pending handshakes"""
        try:
            with open(self.options["pending_file"], "w") as f:
                json.dump(self.pending, f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving pending file: {e}")

    def _connect_gpsd(self):
        """Connect to GPS daemon (non-blocking)"""
        if not HAS_GPSD:
            logging.info("[TripleGeo] gpsd module not available, GPS disabled")
            return

        try:
            logging.info("[TripleGeo] Connecting to gpsd...")
            self.gps_session = gps.gps()
            self.gps_session.stream(gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)
            logging.info("[TripleGeo] Connected to gpsd")
        except Exception as e:
            self.gps_session = None
            logging.warning(f"[TripleGeo] gpsd connection failed: {e}")

    def get_gps_coord(self, max_attempts=3):
        """Get GPS coordinates (quick, non-blocking)"""
        if not self.gps_session:
            return self._gps_last

        try:
            # Quick GPS read with limited attempts
            for _ in range(max_attempts):
                report = self.gps_session.next()
                if (report.get('class') == 'TPV' 
                    and getattr(report, 'mode', 1) >= 2 
                    and hasattr(report, 'lat') and hasattr(report, 'lon')):
                    
                    lat = float(report.lat)
                    lon = float(report.lon)
                    alt = getattr(report, 'alt', None)
                    
                    if alt is not None:
                        self._gps_last = (lat, lon, float(alt))
                    else:
                        self._gps_last = (lat, lon)
                    return self._gps_last
        except StopIteration:
            pass  # No GPS data available
        except Exception as e:
            logging.debug(f"[TripleGeo] GPS read exception: {e}")

        return self._gps_last

    def _report_existing_coords(self):
        """Report existing coordinate files"""
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
                logging.warning(f"[TripleGeo] Glob error for {pattern}: {e}")
        
        if files:
            logging.info(f"[TripleGeo] Found {len(files)} existing coordinate files")

    def on_unload(self, ui):
        """Cleanup when plugin unloads"""
        try:
            self._save_processed()
            self._save_pending()
            if hasattr(self, 'gps_session') and self.gps_session:
                self.gps_session.close()
            logging.info("[TripleGeo] Plugin cleanup completed")
        except Exception as e:
            logging.warning(f"[TripleGeo] Error during cleanup: {e}")
        
        logging.info("[TripleGeo] TripleGeo plugin unloaded")
