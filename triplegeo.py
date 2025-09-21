import logging
import requests
import os
import json
import time
import threading
import glob
import re
import pwnagotchi.plugins as plugins

try:
    import gps
    HAS_GPSD = True
except ImportError:
    HAS_GPSD = False

class TripleGeo(plugins.Plugin):
    __author__ = "disco252"
    __version__ = "2.0-final"
    __license__ = "GPL3"
    __description__ = (
        "Advanced geolocation, AP/client mapping, and Discord notifications for Pwnagotchi. "
        "Uses GPS, Google, or WiGLE; posts detailed events to Discord with IEEE OUI lookup. "
        "FINAL VERSION with proper config access, AP data caching, and BSSID extraction."
    )
    __name__ = "triplegeo"
    __defaults__ = {
        "enabled":             False,
        "mode":                ["gps", "google", "wigle"],
        "google_api_key":      "",
        "wigle_user":          "",
        "wigle_token":         "",
        "handshake_dir":       "/home/pi/handshakes",
        "processed_file":      "/root/.triplegeo_processed",
        "pending_file":        "/root/.triplegeo_pending",
        "wigle_delay":         2,
        "max_wigle_per_minute": 10,
        "wigle_upload":        True,
        "global_log_file":     "/root/triplegeo_globalaplog.jsonl",
        "discord_webhook_url": "",
        "oui_db_path":         "/usr/local/share/pwnagotchi/ieee_oui.txt",
        "cache_expire_minutes": 30,  # How long to keep AP cache
        "debug_logging":       False,  # Enhanced debug logging
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.api_mutex   = threading.Lock()
        self.processed   = set()
        self.pending     = []
        self.gps_session = None
        self._gps_last   = None
        self.oui_db      = {}

        # AP data cache - stores live scanning data for handshake correlation
        self.ap_cache = {}  # mac -> {rssi, channel, encryption, etc.}
        self.ap_cache_lock = threading.Lock()

    def _load_oui_db(self, db_path):
        """Load IEEE OUI database from file"""
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

        logging.info(f"[TripleGeo] Loaded {len(oui_dict)} OUIs from IEEE database")
        return oui_dict

    def _lookup_oui_vendor(self, mac_addr):
        """Look up vendor for a given MAC address"""
        if not mac_addr:
            return "Unknown"
        oui = mac_addr.replace(":", "").replace("-", "").upper()[:6]
        return self.oui_db.get(oui, "Unknown")

    def on_loaded(self):
        """Load plugin configuration - FIXED CONFIG ACCESS"""
        logging.info("[TripleGeo] Loading plugin configuration...")

        # Multiple methods to access configuration - bulletproof approach
        config_loaded = False

        try:
            # Method 1: Standard Pwnagotchi plugin config access
            if hasattr(self, 'config') and self.config is not None:
                for key, default_val in self.__defaults__.items():
                    self.options[key] = self.config.get(key, default_val)
                config_loaded = True
                logging.info("[TripleGeo] Config loaded via self.config")
        except Exception as e:
            logging.warning(f"[TripleGeo] Method 1 config access failed: {e}")

        if not config_loaded:
            try:
                # Method 2: Direct import and access
                import pwnagotchi
                if hasattr(pwnagotchi, 'config') and hasattr(pwnagotchi.config, 'config'):
                    cfg = pwnagotchi.config.config
                    plugin_config = cfg.get('main', {}).get('plugins', {}).get('triplegeo', {})
                    for key, default_val in self.__defaults__.items():
                        self.options[key] = plugin_config.get(key, default_val)
                    config_loaded = True
                    logging.info("[TripleGeo] Config loaded via pwnagotchi.config")
            except Exception as e:
                logging.warning(f"[TripleGeo] Method 2 config access failed: {e}")

        if not config_loaded:
            try:
                # Method 3: Global config access
                import pwnagotchi.config as cfg_module
                if hasattr(cfg_module, 'config') and cfg_module.config:
                    plugin_config = cfg_module.config.get('main', {}).get('plugins', {}).get('triplegeo', {})
                    for key, default_val in self.__defaults__.items():
                        self.options[key] = plugin_config.get(key, default_val)
                    config_loaded = True
                    logging.info("[TripleGeo] Config loaded via global config module")
            except Exception as e:
                logging.warning(f"[TripleGeo] Method 3 config access failed: {e}")

        if not config_loaded:
            try:
                # Method 4: Plugin manager config access
                if hasattr(plugins, '_plugins_config') and plugins._plugins_config:
                    plugin_config = plugins._plugins_config.get('triplegeo', {})
                    for key, default_val in self.__defaults__.items():
                        self.options[key] = plugin_config.get(key, default_val)
                    config_loaded = True
                    logging.info("[TripleGeo] Config loaded via plugin manager")
            except Exception as e:
                logging.warning(f"[TripleGeo] Method 4 config access failed: {e}")

        # Fallback to environment variables and defaults
        if not config_loaded:
            logging.warning("[TripleGeo] All config methods failed, using environment variables and defaults")
            self.options = dict(self.__defaults__)

            # Try to get critical settings from environment
            env_webhook = os.environ.get('TRIPLEGEO_DISCORD_WEBHOOK_URL', '')
            env_enabled = os.environ.get('TRIPLEGEO_ENABLED', 'false').lower() == 'true'

            if env_webhook:
                self.options['discord_webhook_url'] = env_webhook
                self.options['enabled'] = True
                logging.info("[TripleGeo] Using Discord webhook from environment variable")
            elif env_enabled:
                self.options['enabled'] = True
                logging.info("[TripleGeo] Plugin enabled via environment variable")

        # Log configuration status
        logging.info(f"[TripleGeo] Plugin enabled: {self.options['enabled']}")
        webhook_url = self.options.get('discord_webhook_url', '')
        logging.info(f"[TripleGeo] Discord webhook configured: {'Yes' if webhook_url else 'No'}")
        if webhook_url:
            logging.info(f"[TripleGeo] Webhook URL: {webhook_url[:50]}...")
        logging.info(f"[TripleGeo] Mode: {self.options['mode']}")

        if self.options.get('debug_logging', False):
            for key, val in self.options.items():
                if 'webhook' not in key.lower():  # Don't log webhook URL
                    logging.debug(f"[TripleGeo] Config {key} = {val}")

        # Load OUI database
        self.oui_db = self._load_oui_db(self.options["oui_db_path"])

        # Initialize components
        self._load_storage()
        self._connect_gpsd()

        logging.info(f"[TripleGeo] Plugin loaded successfully with {len(self.oui_db)} OUIs.")
        self._report_existing_coords()

    def _extract_info_from_filename(self, filename):
        """Extract AP info from handshake filename patterns"""
        shortname = os.path.basename(filename).replace(".pcap", "")

        if self.options.get('debug_logging', False):
            logging.debug(f"[TripleGeo] Extracting from filename: {shortname}")

        # Pwnagotchi format examples:
        # "SSID_BSSID_HASH.pcap" -> ["SSID", "BSSID", "HASH"] 
        # "PMT_a49733bc3af1_2025-09-20T04-00-02-265.pcap"
        parts = shortname.split("_")
        ssid = parts[0] if parts else shortname

        # Look for MAC-like pattern in parts (12 hex chars = MAC without separators)
        bssid = None
        for part in parts[1:]:  # Skip SSID part
            if re.match(r'^[0-9a-fA-F]{12}$', part):  # 12 hex chars
                # Convert to standard MAC format: ab1234567890 -> ab:12:34:56:78:90
                bssid = ':'.join([part[i:i+2] for i in range(0, 12, 2)])
                break
            elif re.match(r'^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$', part):  # Already formatted
                bssid = part
                break

        if self.options.get('debug_logging', False):
            logging.debug(f"[TripleGeo] Extracted SSID: {ssid}, BSSID: {bssid}")

        return ssid, bssid

    def _cleanup_ap_cache(self):
        """Remove expired entries from AP cache"""
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

            if expired_keys:
                logging.debug(f"[TripleGeo] Cleaned up {len(expired_keys)} expired AP cache entries")

    def on_unfiltered_ap_list(self, agent, data):
        """Process unfiltered AP list and cache AP data for handshake correlation"""
        if not self.options.get("enabled", False):
            return

        if not isinstance(data, dict) or 'wifi' not in data or 'aps' not in data['wifi']:
            return

        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        now = time.time()

        # Cleanup expired cache entries periodically
        if now % 300 < 1:  # Every ~5 minutes
            self._cleanup_ap_cache()

        cached_count = 0
        with self.ap_cache_lock:
            for ap in data['wifi']['aps']:
                ap_mac = ap.get('mac', '')
                if not ap_mac:
                    continue

                # Cache AP data for later handshake correlation
                self.ap_cache[ap_mac] = {
                    'ssid': ap.get('hostname', '<unknown>'),
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

                # Process for immediate webhook (optional)
                ap_ssid = ap.get('hostname', '<unknown>')
                clients = ap.get('clients', [])

                if clients:
                    for client in clients:
                        client_mac = client.get('mac', '')
                        key = f"{ap_mac}|{ap_ssid}|{client_mac}"
                        if key not in self.processed:
                            self._process_ap_entry(ap, client_mac, gps_coord, now, agent)
                            self.processed.add(key)
                else:
                    key = f"{ap_mac}|{ap_ssid}|"
                    if key not in self.processed:
                        self._process_ap_entry(ap, "", gps_coord, now, agent)
                        self.processed.add(key)

        if self.options.get('debug_logging', False) and cached_count > 0:
            logging.debug(f"[TripleGeo] Cached {cached_count} APs, total cache size: {len(self.ap_cache)}")

    def _calculate_frequency(self, channel):
        """Calculate frequency from channel number"""
        if not isinstance(channel, int):
            return "N/A"

        if 1 <= channel <= 14:
            return 2412 + (channel - 1) * 5
        elif 36 <= channel <= 165:
            return 5000 + channel * 5
        elif channel >= 1 and channel <= 233:  # 6 GHz
            return 5955 + (channel - 1) * 5
        return "N/A"

    def _calculate_band(self, channel):
        """Calculate band from channel number"""
        if not isinstance(channel, int):
            return "unknown"

        if 1 <= channel <= 14:
            return "2.4 GHz"
        elif 36 <= channel <= 165:
            return "5 GHz"
        elif channel >= 1 and channel <= 233:
            return "6 GHz"
        return "unknown"

    def _process_ap_entry(self, ap, client_mac, gps_coord, now, agent):
        """Process individual AP entry for logging"""
        rssi = ap.get('rssi', 'N/A')
        channel = ap.get('channel', 'N/A')
        encryption = ap.get('encryption', 'N/A')
        mac = ap.get('mac', '')
        ssid = ap.get('hostname', '<unknown>')

        freq = self._calculate_frequency(channel)
        band = self._calculate_band(channel)

        entry = {
            "timestamp": now,
            "ssid": ssid,
            "bssid": mac,
            "client": client_mac,
            "rssi": rssi,
            "snr": "N/A",
            "channel": channel,
            "frequency": freq,
            "band": band,
            "encryption": encryption,
            "lat": gps_coord[0] if gps_coord else "N/A",
            "lon": gps_coord[1] if gps_coord else "N/A",
            "altitude": gps_coord[2] if gps_coord and len(gps_coord) > 2 else "N/A",
            "source": "gpsd" if gps_coord else "none",
            "vendor": self._lookup_oui_vendor(mac),
            "supported_rates": [],
            "extended_supported_rates": [],
            "vendor_specific_tags": {},
            "pwnagotchi_name": getattr(agent, "name", lambda: "Unknown")(),
            "device_fingerprint": getattr(agent, "fingerprint", lambda: "Unknown")(),
        }

        try:
            with open(self.options["global_log_file"], "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logging.error(f"[TripleGeo] Failed to log: {e}")

    def on_handshake(self, agent, filename, ap, client):
        """Process handshake captures - FINAL VERSION"""
        if not self.options.get("enabled", False):
            logging.info("[TripleGeo] Plugin disabled, skipping handshake processing")
            return

        logging.info(f"[TripleGeo] Processing handshake: {filename}")

        # Enhanced debug logging
        if self.options.get('debug_logging', False):
            logging.debug(f"[TripleGeo] Cache size: {len(self.ap_cache)}")
            logging.debug(f"[TripleGeo] AP object type: {type(ap)}")
            if hasattr(ap, '__dict__'):
                logging.debug(f"[TripleGeo] AP attributes: {list(vars(ap).keys())}")

        gps_coord = self.get_gps_coord() if HAS_GPSD else None
        ssid, bssid = self._extract_info_from_filename(filename)

        # Try to get BSSID from multiple sources with better error handling
        ap_mac = None
        try:
            if hasattr(ap, 'mac') and ap.mac:
                ap_mac = ap.mac
            elif hasattr(ap, 'bssid') and ap.bssid:
                ap_mac = ap.bssid
            elif isinstance(ap, dict):
                ap_mac = ap.get('mac') or ap.get('bssid')
        except Exception as e:
            logging.warning(f"[TripleGeo] Error extracting MAC from AP object: {e}")

        # Fallback to filename extraction
        if not ap_mac and bssid:
            ap_mac = bssid

        logging.info(f"[TripleGeo] Handshake AP MAC: {ap_mac}, SSID: {ssid}")

        # Look up cached AP data with better error handling
        cached_ap = {}
        if ap_mac:
            try:
                with self.ap_cache_lock:
                    cached_ap = self.ap_cache.get(ap_mac, {})
                    if cached_ap:
                        logging.info(f"[TripleGeo] ✅ Found cached data for {ap_mac}")
                        if self.options.get('debug_logging', False):
                            logging.debug(f"[TripleGeo] Cached data: {cached_ap}")
                    else:
                        logging.warning(f"[TripleGeo] ❌ No cached data for {ap_mac}")
                        if self.options.get('debug_logging', False):
                            cached_macs = list(self.ap_cache.keys())[:5]  # Show first 5
                            logging.debug(f"[TripleGeo] Available cached MACs: {cached_macs}")
            except Exception as e:
                logging.error(f"[TripleGeo] Error accessing cache: {e}")

        # Extract data with comprehensive fallback hierarchy
        try:
            rssi = cached_ap.get('rssi') or getattr(ap, 'rssi', None) or "N/A"
            channel = cached_ap.get('channel') or getattr(ap, 'channel', None) or "N/A"
            encryption = cached_ap.get('encryption') or getattr(ap, 'encryption', None) or "N/A"
            frequency = cached_ap.get('frequency') or self._calculate_frequency(channel)
            band = cached_ap.get('band') or self._calculate_band(channel)
            vendor = cached_ap.get('vendor') or (self._lookup_oui_vendor(ap_mac) if ap_mac else "Unknown")
        except Exception as e:
            logging.error(f"[TripleGeo] Error extracting AP data: {e}")
            rssi = channel = encryption = frequency = "N/A"
            band = "unknown"
            vendor = "Unknown"

        # Calculate SNR with error handling
        snr = "N/A"
        try:
            noise = getattr(ap, "noise", None)
            if isinstance(rssi, (int, float)) and isinstance(noise, (int, float)):
                snr = rssi - noise
            elif isinstance(rssi, (int, float)) and rssi != 0:
                estimated_noise = -95  # Typical noise floor
                snr = rssi - estimated_noise
        except Exception as e:
            logging.warning(f"[TripleGeo] Error calculating SNR: {e}")

        # Use cached GPS if current GPS unavailable
        if not gps_coord and cached_ap.get('gps_coord'):
            gps_coord = cached_ap['gps_coord']

        # Get client MAC with error handling
        client_mac = ""
        try:
            if client and hasattr(client, 'mac'):
                client_mac = client.mac
            elif isinstance(client, dict):
                client_mac = client.get('mac', '')
        except Exception as e:
            logging.warning(f"[TripleGeo] Error extracting client MAC: {e}")

        entry = {
            "timestamp":        time.time(),
            "ssid":             ssid,
            "bssid":            ap_mac or "Unknown",
            "client":           client_mac,
            "rssi":             rssi,
            "snr":              snr,
            "channel":          channel,
            "frequency":        frequency,
            "band":             band,
            "encryption":       encryption,
            "lat":              gps_coord[0] if gps_coord else "N/A",
            "lon":              gps_coord[1] if gps_coord else "N/A",
            "altitude":         gps_coord[2] if gps_coord and len(gps_coord) > 2 else "N/A",
            "source":           "gpsd" if gps_coord else "none",
            "vendor":           vendor,
            "handshake_file":   filename,
            "supported_rates":            getattr(ap, "supported_rates", []),
            "extended_supported_rates":   getattr(ap, "extended_supported_rates", []),
            "vendor_specific_tags":       getattr(ap, "vendor_specific", {}),
            "pwnagotchi_name":  getattr(agent, "name", lambda:"Unknown")(),
            "device_fingerprint": getattr(agent, "fingerprint", lambda:"Unknown")(),
        }

        # Log what we extracted
        logging.info(f"[TripleGeo] Extracted - RSSI: {rssi}, Channel: {channel}, Freq: {frequency}, Enc: {encryption}, Band: {band}")

        # Save GPS coordinates if available  
        if gps_coord:
            coord_file = filename.replace(".pcap", ".triplegeo.coord.json")
            coord_data = {"coord": {"lat": gps_coord[0], "lon": gps_coord[1]}, "source": "gpsd"}
            if len(gps_coord) > 2:
                coord_data["coord"]["altitude"] = gps_coord[2]
            try:
                with open(coord_file, "w") as f:
                    json.dump(coord_data, f)
            except Exception as e:
                logging.warning(f"[TripleGeo] Could not save coord file: {e}")

        # Save state
        try:
            self.pending.append(filename)
            self._save_pending()
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving pending: {e}")

        logging.info(f"[TripleGeo] Triggering Discord webhook for handshake: {ssid}")
        self.send_discord_webhook(entry, title=":handshake: New Handshake Captured")

    def send_discord_webhook(self, event, title=":satellite: New Event"):
        """Send Discord webhook with complete data"""
        url = self.options.get("discord_webhook_url", "")
        if not url:
            logging.warning("[TripleGeo] No Discord webhook URL configured - cannot send notification")
            return

        logging.info(f"[TripleGeo] Preparing Discord webhook: {title}")

        try:
            ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(event["timestamp"]))

            rates = event.get("supported_rates", [])
            ext_rates = event.get("extended_supported_rates", [])
            all_rates = rates + ext_rates if isinstance(rates, list) and isinstance(ext_rates, list) else []
            rates_str = ", ".join([f"{r} Mbps" for r in all_rates[:5]]) if all_rates else "N/A"

            vendor_tags = event.get("vendor_specific_tags", {})
            vendor_str = ", ".join([f"{k}: {v}" for k, v in vendor_tags.items()][:3]) if vendor_tags else "N/A"

            gps_status = "GPS" if event.get("source") == "gpsd" else "No GPS"

            fields = [
                {"name":"SSID","value":str(event["ssid"]),"inline":True},
                {"name":"BSSID","value":str(event["bssid"]),"inline":True},
                {"name":"Client","value":str(event.get("client","None")),"inline":True},
                {"name":"Signal","value":f"{event.get('rssi','N/A')} dBm","inline":True},
                {"name":"SNR","value":f"{event.get('snr','N/A')} dB","inline":True},
                {"name":"Channel","value":str(event.get("channel","N/A")),"inline":True},
                {"name":"Frequency","value":f"{event.get('frequency','N/A')} MHz","inline":True},
                {"name":"Band","value":str(event.get("band","unknown")),"inline":True},
                {"name":"Encryption","value":str(event.get("encryption","N/A")),"inline":True},
                {"name":"Vendor","value":str(event.get("vendor","Unknown")),"inline":True},
                {"name":"Timestamp","value":ts,"inline":True},
                {"name":"Location","value":f"{gps_status}\n{event.get('lat','N/A')},{event.get('lon','N/A')}","inline":True},
                {"name":"Altitude","value":f"{event.get('altitude','N/A')} m","inline":True},
                {"name":"Source","value":str(event.get("source","none")),"inline":True},
                {"name":"Supported Rates","value":rates_str,"inline":False},
                {"name":"Vendor Tags","value":vendor_str,"inline":False},
                {"name":"File","value":str(event.get("handshake_file","")),"inline":False},
            ]

            # Color coding: Green for GPS, Orange for no GPS, Red for missing data
            color = 0x00ff00 if event.get("source") == "gpsd" else 0xff6600
            if event.get('rssi') == 'N/A' and event.get('channel') == 'N/A':
                color = 0xff0000  # Red for missing technical data

            payload = {
                "embeds": [
                    {
                        "title": title,
                        "fields": fields,
                        "color": color,
                        "footer": {"text": f"triplegeo v{self.__version__} | {gps_status} | Cached: {len(self.ap_cache)} APs"}
                    }
                ]
            }

            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                logging.info(f"[TripleGeo] Discord webhook sent successfully!")
            else:
                logging.warning(f"[TripleGeo] Webhook failed: {r.status_code} - {r.text[:200]}")

        except Exception as e:
            logging.error(f"[TripleGeo] Webhook error: {e}")

    def _report_existing_coords(self):
        """Report existing coordinate files"""
        webhook_url = self.options.get('discord_webhook_url', '')
        if not webhook_url:
            logging.info("[TripleGeo] No Discord webhook URL configured for coord reporting")
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
                logging.warning(f"[TripleGeo] Error globbing pattern {pattern}: {e}")

        if not files:
            logging.info("[TripleGeo] No existing coord.json files to report.")
            return

        logging.info(f"[TripleGeo] Found {len(files)} existing coord.json files.")

    def _load_storage(self):
        """Load processed handshakes and pending files"""
        # Load processed file
        pf = self.options["processed_file"]
        self.processed = set()
        if os.path.exists(pf):
            try:
                with open(pf, 'r') as f:
                    self.processed = set(json.load(f))
                logging.debug(f"[TripleGeo] Loaded {len(self.processed)} processed entries")
            except Exception as e:
                logging.warning(f"[TripleGeo] Error loading processed file: {e}")
                try:
                    with open(pf, "w") as f:
                        json.dump([], f)
                except Exception:
                    pass

        # Load pending file
        pend = self.options["pending_file"]
        self.pending = []
        if os.path.exists(pend):
            try:
                with open(pend, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.pending = json.loads(content)
                    else:
                        self.pending = []
                logging.debug(f"[TripleGeo] Loaded {len(self.pending)} pending entries")
            except Exception as e:
                logging.warning(f"[TripleGeo] Error loading pending file: {e}")
                try:
                    with open(pend, "w") as f:
                        json.dump([], f)
                except Exception:
                    pass

    def _save_pending(self):
        """Save pending handshakes"""
        try:
            with open(self.options["pending_file"], "w") as f:
                json.dump(self.pending, f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving pending: {e}")

    def _connect_gpsd(self):
        """Connect to GPS daemon"""
        if not HAS_GPSD:
            logging.warning("[TripleGeo] gpsd-py3 module not found; GPS disabled.")
            return

        try:
            logging.info("[TripleGeo] Connecting to local gpsd socket")
            self.gps_session = gps.gps()
            self.gps_session.stream(gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)
            logging.info("[TripleGeo] Connected to gpsd for GPS.")
        except Exception as e:
            self.gps_session = None
            logging.warning(f"[TripleGeo] Could not connect to gpsd: {e}")

    def get_gps_coord(self, max_attempts=10):
        """Get GPS coordinates with proper error handling"""
        if not self.gps_session:
            return self._gps_last

        try:
            for _ in range(max_attempts):
                report = self.gps_session.next()
                if (report.get('class') == 'TPV' and 
                    getattr(report, 'mode', 1) >= 2 and 
                    hasattr(report, 'lat') and hasattr(report, 'lon')):

                    lat = float(report.lat)
                    lon = float(report.lon)
                    alt = getattr(report, 'alt', None)

                    if alt is not None:
                        self._gps_last = (lat, lon, float(alt))
                    else:
                        self._gps_last = (lat, lon)
                    return self._gps_last

        except StopIteration:
            logging.debug("[TripleGeo] No GPS data available")
        except Exception as e:
            logging.warning(f"[TripleGeo] GPS exception: {e}")

        return self._gps_last

    def _geolocate(self, data):
        """Placeholder for geolocation methods"""
        for method in self.options["mode"]:
            if method == "gps":
                coord = self.get_gps_coord()
                if coord:
                    return coord, "gps"
            elif method == "google":
                key = self.options["google_api_key"]
                if key and data:
                    pass  # implement Google API call
            elif method == "wigle":
                user, token = self.options["wigle_user"], self.options["wigle_token"]
                if user and token and data:
                    pass  # implement WiGLE API call
        return None, None

    def _save_processed(self):
        """Save processed entries to file"""
        try:
            with open(self.options["processed_file"], "w") as f:
                json.dump(list(self.processed), f)
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving processed: {e}")

    def on_unload(self, ui):
        """Clean up when plugin unloads"""
        try:
            self._save_processed()
            self._save_pending()
            if hasattr(self, 'gps_session') and self.gps_session:
                self.gps_session.close()
            logging.info("[TripleGeo] Plugin cleanup completed")
        except Exception as e:
            logging.warning(f"[TripleGeo] Error during unload: {e}")
        logging.info("[TripleGeo] Plugin unloaded")
