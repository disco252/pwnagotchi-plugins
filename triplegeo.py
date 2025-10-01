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
    __version__ = "1.8.3"  # Incremented for webgps compatibility
    __license__ = "GPL3"
    __description__ = (
        "Enhanced geolocation and Discord notifications for Pwnagotchi handshake captures."
        "AP data collection and correlation for Discord reporting. Now with webgpsmap compatibility."
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
        "cache_expire_minutes": 60,  # Increased cache time
        "debug_logging": True,  # Enable debug logging
        "webgps_compatible": True,  # Enable webgpsmap compatibility
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

    def _create_webgps_file(self, filename, gps_coord):
        """Create webgps-compatible .gps.json file for webgpsmap plugin"""
        if not self.options.get('webgps_compatible', True):
            return
            
        if not gps_coord or len(gps_coord) < 2:
            logging.debug("[TripleGeo] No GPS coordinates available for webgps file")
            return
            
        try:
            # Create .gps.json filename (webgpsmap expects this format)
            gps_file = filename.replace('.pcap', '.gps.json')
            
            # Build webgps-compatible data structure
            webgps_data = {
                'lat': float(gps_coord[0]),
                'lng': float(gps_coord[1]),  # webgpsmap uses 'lng', not 'lon'
                'accuracy': 10.0,  # Default accuracy in meters
                'timestamp': time.time()
            }
            
            # Add altitude if available
            if len(gps_coord) > 2 and gps_coord[2] is not None:
                webgps_data['altitude'] = float(gps_coord[2])
            
            # Write the webgps file
            with open(gps_file, 'w') as f:
                json.dump(webgps_data, f)
                
            logging.info(f"[TripleGeo] Created webgps file: {os.path.basename(gps_file)}")
            
        except Exception as e:
            logging.warning(f"[TripleGeo] Could not create webgps file: {e}")

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
        expire_time = time.time() - (self.options.get('cache_expire_minutes', 60) * 60)
        with self.ap_cache_lock:
            expired_keys = [
                mac for mac, data in self.ap_cache.items()
                if data.get('timestamp', 0) < expire_time
            ]
            for mac in expired_keys:
                del self.ap_cache[mac]
            if expired_keys:
                logging.info(f"[TripleGeo] Cleaned up {len(expired_keys)} expired AP cache entries")

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
        
        # Add cache status for debugging
        cache_status = "Cached" if event.get("from_cache") else "Direct"
        fields.append({"name": "Data Source", "value": cache_status, "inline": True})
        
        # Color based on data completeness
        color = 0x00ff00  # Green for complete data
        if event.get('rssi') == 'N/A' or event.get('channel') == 'N/A':
            color = 0xff6600  # Orange for missing technical data
        if lat == 'N/A' or lon == 'N/A':
            color = 0xff9900  # Different orange for no GPS
        
        return {
            "title": safe_str(title, 256),
            "fields": fields[:25],  # Discord max 25 fields
            "color": color,
            "footer": {"text": f"triplegeo v{self.__version__} | Handshake #{self.handshake_count} | Cache: {event.get('cache_size', 0)} APs | WebGPS: {'✓' if self.options.get('webgps_compatible', True) else '✗'}"}
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
        logging.info(f"[TripleGeo] Debug logging: {self.options.get('debug_logging', False)}")
        logging.info(f"[TripleGeo] WebGPS compatibility: {self.options.get('webgps_compatible', True)}")
        if webhook_url:
            logging.info(f"[TripleGeo] Webhook URL: {webhook_url[:50]}...")

        # Initialize components
        self.oui_db = self._load_oui_db(self.options["oui_db_path"])
        self._load_storage()
        self._connect_gpsd()
        
        logging.info(f"[TripleGeo] TripleGeo plugin loaded successfully")

    def on_unfiltered_ap_list(self, agent, data):
        """Enhanced AP data caching with better logging"""
        if not self.options.get("enabled", False):
            return

        if not isinstance(data, dict) or 'wifi' not in data or 'aps' not in data['wifi']:
            logging.debug("[TripleGeo] Invalid or empty AP data received")
            return

        # Get GPS coordinates once for this scan
        gps_coord = None
        if HAS_GPSD and self.gps_session:
            try:
                gps_coord = self.get_gps_coord(max_attempts=2)  # Reduced attempts
                if gps_coord:
                    logging.debug(f"[TripleGeo] GPS coordinates: {gps_coord}")
            except Exception as e:
                logging.debug(f"[TripleGeo] GPS read error: {e}")

        now = time.time()

        # Periodic cache cleanup
        if now % 300 < 1:  # Every ~5 minutes
            self._cleanup_ap_cache()

        cached_count = 0
        aps_with_data = 0
        
        with self.ap_cache_lock:
            for ap in data['wifi']['aps']:
                ap_mac = ap.get('mac', '')
                if not ap_mac:
                    continue

                # Extract comprehensive data with better error handling
                ssid = ap.get('hostname', 'Hidden')
                rssi = ap.get('rssi')
                channel = ap.get('channel')
                encryption = ap.get('encryption', 'Open')
                
                # Log detailed AP data for debugging
                if self.options.get('debug_logging', False):
                    logging.debug(f"[TripleGeo] Caching AP {ap_mac}: SSID={ssid}, RSSI={rssi}, CH={channel}, ENC={encryption}")
                
                # Cache comprehensive AP data
                ap_data = {
                    'ssid': ssid,
                    'rssi': rssi if rssi is not None else "N/A",
                    'channel': channel if channel is not None else "N/A",
                    'encryption': encryption,
                    'frequency': self._calculate_frequency(channel),
                    'band': self._calculate_band(channel),
                    'vendor': self._lookup_oui_vendor(ap_mac),
                    'timestamp': now,
                    'gps_coord': gps_coord,
                    'clients': ap.get('clients', [])
                }
                
                self.ap_cache[ap_mac] = ap_data
                cached_count += 1
                
                # Count APs with actual signal data
                if rssi is not None and channel is not None:
                    aps_with_data += 1

        if cached_count > 0:
            logging.info(f"[TripleGeo] Cached {cached_count} APs ({aps_with_data} with signal data), total cache: {len(self.ap_cache)}")

    def on_handshake(self, agent, filename, ap, client):
        """Enhanced handshake processing with improved data extraction and webgps file creation"""
        if not self.options.get("enabled", False):
            logging.info("[TripleGeo] Plugin disabled, skipping handshake")
            return

        self.handshake_count += 1
        logging.info(f"[TripleGeo] ============ Processing handshake #{self.handshake_count} ============")
        logging.info(f"[TripleGeo] Handshake file: {os.path.basename(filename)}")

        # Debug AP object structure
        if self.options.get('debug_logging', False):
            logging.debug(f"[TripleGeo] AP object type: {type(ap)}")
            if hasattr(ap, '__dict__'):
                logging.debug(f"[TripleGeo] AP attributes: {vars(ap)}")
            elif isinstance(ap, dict):
                logging.debug(f"[TripleGeo] AP dict contents: {ap}")

        # Get current GPS coordinates (non-blocking)
        gps_coord = None
        if HAS_GPSD and self.gps_session:
            try:
                gps_coord = self.get_gps_coord(max_attempts=2)
                if gps_coord:
                    logging.info(f"[TripleGeo] Current GPS: {gps_coord}")
            except Exception as e:
                logging.debug(f"[TripleGeo] GPS error during handshake: {e}")

        # Extract SSID and BSSID from filename
        ssid, bssid = self._extract_info_from_filename(filename)
        logging.info(f"[TripleGeo] From filename - SSID: '{ssid}', BSSID: {bssid}")

        # Get AP MAC from multiple sources with enhanced extraction
        ap_mac = None
        ap_ssid = None
        
        try:
            # Try different attribute names
            for attr in ['mac', 'bssid', 'address']:
                if hasattr(ap, attr):
                    ap_mac = getattr(ap, attr)
                    if ap_mac:
                        break
            
            # Try SSID extraction
            for attr in ['ssid', 'hostname', 'name']:
                if hasattr(ap, attr):
                    ap_ssid = getattr(ap, attr)
                    if ap_ssid:
                        break
            
            # Try dict access if object access failed
            if not ap_mac and isinstance(ap, dict):
                ap_mac = ap.get('mac') or ap.get('bssid') or ap.get('address')
            
            if not ap_ssid and isinstance(ap, dict):
                ap_ssid = ap.get('ssid') or ap.get('hostname') or ap.get('name')
                
        except Exception as e:
            logging.warning(f"[TripleGeo] Error extracting AP data: {e}")

        # Fallback to filename extraction
        if not ap_mac and bssid:
            ap_mac = bssid
        if not ap_ssid and ssid:
            ap_ssid = ssid

        logging.info(f"[TripleGeo] Final AP identifiers - MAC: {ap_mac}, SSID: '{ap_ssid}'")

        # Look up cached AP data with debug info
        cached_ap = {}
        from_cache = False
        
        if ap_mac:
            try:
                with self.ap_cache_lock:
                    cached_ap = self.ap_cache.get(ap_mac, {})
                    if cached_ap:
                        from_cache = True
                        cache_age = time.time() - cached_ap.get('timestamp', 0)
                        logging.info(f"[TripleGeo] Found cached data for {ap_mac} (age: {cache_age:.1f}s)")
                        logging.info(f"[TripleGeo] Cached data: RSSI={cached_ap.get('rssi')}, CH={cached_ap.get('channel')}, ENC={cached_ap.get('encryption')}")
                    else:
                        logging.warning(f"[TripleGeo] No cached data for {ap_mac}")
                        logging.info(f"[TripleGeo] Available cache keys: {list(self.ap_cache.keys())[:10]}...")  # Show first 10
            except Exception as e:
                logging.error(f"[TripleGeo] Cache access error: {e}")

        # Extract technical data with enhanced fallback logic
        rssi = "N/A"
        channel = "N/A"
        encryption = "N/A"
        
        try:
            # Try cached data first
            if cached_ap:
                rssi = cached_ap.get('rssi', "N/A")
                channel = cached_ap.get('channel', "N/A")
                encryption = cached_ap.get('encryption', "N/A")
                
            # Try direct AP object extraction as fallback
            if rssi == "N/A" or rssi is None:
                for attr in ['rssi', 'signal', 'signal_strength']:
                    if hasattr(ap, attr):
                        rssi = getattr(ap, attr)
                        if rssi is not None:
                            break
                if isinstance(ap, dict) and rssi == "N/A":
                    rssi = ap.get('rssi') or ap.get('signal') or ap.get('signal_strength') or "N/A"
            
            if channel == "N/A" or channel is None:
                for attr in ['channel', 'ch', 'frequency']:
                    if hasattr(ap, attr):
                        channel = getattr(ap, attr)
                        if channel is not None:
                            break
                if isinstance(ap, dict) and channel == "N/A":
                    channel = ap.get('channel') or ap.get('ch') or "N/A"
                    
            if encryption == "N/A" or not encryption:
                for attr in ['encryption', 'auth', 'security', 'cipher']:
                    if hasattr(ap, attr):
                        encryption = getattr(ap, attr)
                        if encryption:
                            break
                if isinstance(ap, dict) and encryption == "N/A":
                    encryption = ap.get('encryption') or ap.get('auth') or ap.get('security') or "N/A"
            
            # Calculate derived values
            frequency = cached_ap.get('frequency') or self._calculate_frequency(channel)
            band = cached_ap.get('band') or self._calculate_band(channel)
            vendor = cached_ap.get('vendor') or (self._lookup_oui_vendor(ap_mac) if ap_mac else "Unknown")
            
        except Exception as e:
            logging.error(f"[TripleGeo] Data extraction error: {e}")
            rssi = channel = encryption = frequency = "N/A"
            band = "unknown"
            vendor = "Unknown"

        # Calculate SNR with improved logic
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

        # Get client MAC with better extraction
        client_mac = ""
        try:
            if client:
                if hasattr(client, 'mac'):
                    client_mac = client.mac
                elif isinstance(client, dict):
                    client_mac = client.get('mac', '')
                elif isinstance(client, str):
                    client_mac = client
        except Exception as e:
            logging.debug(f"[TripleGeo] Client MAC extraction error: {e}")

        # Build event data with enhanced debugging info
        entry = {
            "timestamp": time.time(),
            "ssid": ap_ssid or ssid,
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
            "vendor": vendor,
            "from_cache": from_cache,
            "cache_size": len(self.ap_cache)
        }

        # Log comprehensive technical details
        logging.info(f"[TripleGeo] Final technical data:")
        logging.info(f"[TripleGeo]   RSSI: {rssi} dBm")
        logging.info(f"[TripleGeo]   Channel: {channel}")
        logging.info(f"[TripleGeo]   Frequency: {frequency} MHz")
        logging.info(f"[TripleGeo]   Band: {band}")
        logging.info(f"[TripleGeo]   Encryption: {encryption}")
        logging.info(f"[TripleGeo]   Vendor: {vendor}")
        logging.info(f"[TripleGeo]   Data source: {'Cache' if from_cache else 'Direct'}")

        # Save GPS coordinates to files if available
        if gps_coord:
            # Save triplegeo format
            coord_file = filename.replace(".pcap", ".triplegeo.coord.json")
            coord_data = {
                "coord": {"lat": gps_coord[0], "lon": gps_coord[1]},
                "source": "gpsd",
                "timestamp": time.time()
            }
            if len(gps_coord) > 2:
                coord_data["coord"]["altitude"] = gps_coord[2]
                
            try:
                with open(coord_file, "w") as f:
                    json.dump(coord_data, f)
                logging.info(f"[TripleGeo] Saved coordinates to {os.path.basename(coord_file)}")
                
                # CREATE WEBGPS COMPATIBLE FILE
                self._create_webgps_file(filename, gps_coord)
                
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
        logging.info(f"[TripleGeo] Sending handshake to Discord: {ap_ssid or ssid}")
        success = self.send_discord_webhook(entry, title="New Handshake Captured")
        
        if success:
            logging.info(f"[TripleGeo] Successfully sent handshake #{self.handshake_count} to Discord")
        else:
            logging.error(f"[TripleGeo] Failed to send handshake #{self.handshake_count} to Discord")
        
        logging.info(f"[TripleGeo] ============ Handshake #{self.handshake_count} Complete ============")

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
                logging.debug(f"[TripleGeo] Discord response text: {r.text}")

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
        if channel == "N/A" or channel is None:
            return "N/A"
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
        if channel == "N/A" or channel is None:
            return "unknown"
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

    def get_gps_coord(self, max_attempts=2):
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
            os.path.join(hd, "*.coord.json"),
            os.path.join(hd, "*.gps.json")  # Include webgps files
        ]
        files = []
        for pattern in patterns:
            try:
                files.extend(glob.glob(pattern))
            except Exception as e:
                logging.warning(f"[TripleGeo] Glob error for {pattern}: {e}")
        
        if files:
            logging.info(f"[TripleGeo] Found {len(files)} existing coordinate files")
            
            # Count different file types
            triplegeo_files = len([f for f in files if '.triplegeo.coord.json' in f])
            webgps_files = len([f for f in files if '.gps.json' in f and '.triplegeo.coord.json' not in f])
            logging.info(f"[TripleGeo] TripleGeo files: {triplegeo_files}, WebGPS files: {webgps_files}")

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
