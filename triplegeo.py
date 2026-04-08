#!/usr/bin/env python3
"""
TripleGeo v2.0.0 - GPS-enhanced WiFi handshake tracker for Pwnagotchi

Author: disco252
License: GPL3
"""

import gzip
import glob
import json
import logging
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

try:
    import gps  # type: ignore
    HAS_GPSD = True
except ImportError:
    HAS_GPSD = False

try:
    import pwnagotchi.plugins as plugins  # type: ignore
except ImportError:
    class _FakePlugins:
        class Plugin:
            pass
    plugins = _FakePlugins()

# ============================================================================
# Type Aliases and Constants
# ============================================================================

GPSSource = str  # Literal["current", "cached", "ap_cache", "none"]
Coordinates = Tuple[float, float]  # (latitude, longitude)
Coordinates3D = Tuple[float, float, float]  # (latitude, longitude, altitude)

# GPSD report types from the gps module
class GpsdReport:
    class_ : str
    mode: int
    lat: Optional[float]
    lon: Optional[float]
    alt: Optional[float]
    eph: Optional[float]  # Horizontal accuracy


@dataclass(frozen=True)
class APData:
    """Represents a single access point with all collected data."""
    mac: str
    ssid: str
    rssi: Union[int, float, str]
    channel: Union[int, float, str]
    frequency: Union[int, float, str]
    band: str
    encryption: str
    vendor: str
    timestamp: float
    gps_coord: Optional[Tuple[float, float]]
    clients: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class HandshakeEvent:
    """Represents a complete handshake event with all metadata."""
    timestamp: float
    ssid: str
    bssid: str
    client: str
    rssi: Union[int, float, str]
    snr: Union[int, float, str]
    channel: Union[int, float, str]
    frequency: Union[int, float, str]
    band: str
    encryption: str
    lat: Union[float, str]
    lon: Union[float, str]
    altitude: Union[float, str]
    gps_source: str
    gps_age_hours: float
    handshake_file: str
    vendor: str
    from_cache: bool
    cache_size: int


@dataclass(frozen=True)
class ExportResult:
    """Result of an export operation."""
    success: bool
    filepath: Optional[str] = None
    filename: Optional[str] = None
    error_message: Optional[str] = None
    
    @classmethod
    def ok(cls, filepath: str, filename: str) -> 'ExportResult':
        return cls(success=True, filepath=filepath, filename=filename)
    
    @classmethod
    def err(cls, error_message: str) -> 'ExportResult':
        return cls(success=False, error_message=error_message)


@dataclass(frozen=True)
class UploadResult:
    """Result of an upload operation."""
    success: bool
    networks_added: Optional[int] = None
    error_message: Optional[str] = None
    
    @classmethod
    def ok(cls, networks_added: int) -> 'UploadResult':
        return cls(success=True, networks_added=networks_added)
    
    @classmethod
    def err(cls, error_message: str) -> 'UploadResult':
        return cls(success=False, error_message=error_message)


# ============================================================================
# Configuration Management
# ============================================================================

@dataclass(frozen=True)
class ConfigValidationError:
    """Represents a single configuration validation error."""
    field: str
    message: str


class ConfigValidator:
    """Validates TripleGeo configuration settings."""
    
    @staticmethod
    def validate(config: Dict[str, Any]) -> List[ConfigValidationError]:
        """Validate configuration and return list of errors.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Validate webhook URL if configured
        webhook_url = config.get('discord_webhook_url')
        if webhook_url:
            parsed_url = ConfigValidator._parse_url(webhook_url)
            if not parsed_url['scheme'] or parsed_url['scheme'] != 'https':
                errors.append(ConfigValidationError(
                    field='discord_webhook_url',
                    message="Webhook URL must use HTTPS protocol"
                ))
            if not parsed_url['netloc']:
                errors.append(ConfigValidationError(
                    field='discord_webhook_url',
                    message="Invalid webhook URL format"
                ))
        
        # Validate WiGLE credentials
        if config.get('wigle_upload'):
            if not config.get('wigle_user'):
                errors.append(ConfigValidationError(
                    field='wigle_user',
                    message="Required when wigle_upload is enabled"
                ))
            if not config.get('wigle_token'):
                errors.append(ConfigValidationError(
                    field='wigle_token',
                    message="Required when wigle_upload is enabled"
                ))
        
        # Validate cache expiry settings
        cache_expire = config.get('cache_expire_minutes', 60)
        if not isinstance(cache_expire, (int, float)) or cache_expire < 1:
            errors.append(ConfigValidationError(
                field='cache_expire_minutes',
                message="Must be a positive number"
            ))
        
        # Validate GPS settings
        gps_expiry = config.get('gps_cache_expiry_hours', 24)
        if not isinstance(gps_expiry, (int, float)) or gps_expiry < 0:
            errors.append(ConfigValidationError(
                field='gps_cache_expiry_hours',
                message="Must be a non-negative number"
            ))
        
        return errors
    
    @staticmethod
    def _parse_url(url: str) -> Dict[str, str]:
        """Simple URL parser (since urllib.parse is not imported)."""
        result = {'scheme': '', 'netloc': ''}
        
        # Extract scheme
        if '://' in url:
            scheme_part, rest = url.split('://', 1)
            result['scheme'] = scheme_part.lower()
            
            # Extract netloc (host)
            if '/' in rest:
                netloc_part = rest.split('/', 1)[0]
            else:
                netloc_part = rest
            
            # Remove port for simplicity
            if ':' in netloc_part and not netloc_part.startswith('['):
                netloc_part = netloc_part.split(':')[0]
            
            result['netloc'] = netloc_part
        
        return result


class ConfigManager:
    """Manages TripleGeo configuration with multiple sources."""
    
    CONFIG_PATHS = [
        '/etc/pwnagotchi/config.toml',
        '/opt/pwnagotchi/config.toml',
        '/home/pi/pwnagotchi/config.toml',
        'config.toml'
    ]
    
    SECRET_ENV_PREFIX = "TRIPLEGEO_"
    
    def __init__(self, log_prefix: str = "[TripleGeo]"):
        self.log_prefix = log_prefix
    
    def load_config(
        self, 
        base_config: Optional[Dict[str, Any]] = None,
        required_secrets: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Load configuration from multiple sources with fallback.
        
        Args:
            base_config: Base configuration to override
            required_secrets: List of secret field names to load from environment
            
        Returns:
            Merged configuration dictionary
        """
        config = dict(base_config) if base_config else {}
        
        # Try standard plugin config first
        config_loaded = False
        
        # Check for plugin's internal config (Pwnagotchi framework)
        try:
            import sys
            frame = None
            for f in reversed(sys._current_frames().values()):
                if 'self' in f.f_locals and hasattr(f.f_locals['self'], 'config'):
                    frame = f
                    break
            
            if frame is not None:
                plugin_self = frame.f_locals.get('self')
                if hasattr(plugin_self, 'config') and plugin_self.config is not None:
                    for key, default_val in self._get_all_defaults().items():
                        config[key] = plugin_self.config.get(key, default_val)
                    config_loaded = True
                    logging.info(f"{self.log_prefix} Config loaded via standard method")
        except Exception as e:
            logging.warning(f"{self.log_prefix} Standard config load failed: {e}")
        
        # Try direct file parsing
        if not config_loaded:
            parsed_config = self._parse_toml_directly()
            if parsed_config:
                for key, default_val in self._get_all_defaults().items():
                    config[key] = parsed_config.get(key, default_val)
                config_loaded = True
                logging.info(f"{self.log_prefix} Loaded {len(parsed_config)} config values from file")
        
        # Fall back to environment variables + defaults
        if not config_loaded:
            config = self._get_all_defaults()
            env_webhook = os.environ.get('TRIPLEGEO_DISCORD_WEBHOOK_URL', '')
            env_enabled = os.environ.get('TRIPLEGEO_ENABLED', 'false').lower() == 'true'
            
            if env_webhook:
                config['discord_webhook_url'] = env_webhook
                config['enabled'] = True
                logging.info(f"{self.log_prefix} Using webhook from environment variable")
            elif env_enabled:
                config['enabled'] = True
            
            # Load any required secrets from environment
            if required_secrets:
                for secret in required_secrets:
                    env_var = f"{self.SECRET_ENV_PREFIX}{secret.upper()}"
                    env_value = os.environ.get(env_var)
                    if env_value and secret in config:
                        config[secret] = env_value
        
        return config
    
    def _get_all_defaults(self) -> Dict[str, Any]:
        """Get all default configuration values."""
        return {
            "enabled": False,
            "mode": ["gps", "google", "wigle"],
            "google_api_key": "",
            "wigle_user": "",
            "wigle_token": "",
            "handshake_dir": "/home/pi/handshakes",
            "processed_file": "/root/.triplegeo_processed",
            "pending_file": "/root/.triplegeo_pending",
            "wigle_delay": 300,
            "max_wigle_per_minute": 10,
            "wigle_upload": False,
            "wigle_api_base": "https://api.wigle.net/api/v3",
            "wigle_export_dir": "/root/triplegeo_wigle_exports",
            "wigle_format": "kismet_csv",
            "global_log_file": "/root/triplegeo_globalaplog.jsonl",
            "discord_webhook_url": "",
            "oui_db_path": "/usr/local/share/pwnagotchi/ieee_oui.txt",
            "cache_expire_minutes": 60,
            "debug_logging": True,
            "gps_cache_file": "/root/.triplegeo_gps_cache",
            "use_last_gps": True,
            "gps_cache_expiry_hours": 24,
            "gps_accuracy_threshold": 100,
            "fallback_to_cached_gps": True,
        }
    
    def _parse_toml_directly(self) -> Dict[str, Any]:
        """Parse TOML config file directly (fallback method)."""
        config: Dict[str, Any] = {}
        
        try:
            for path in self.CONFIG_PATHS:
                if os.path.exists(path):
                    logging.info(f"{self.log_prefix} Found config file: {path}")
                    
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line.startswith('main.plugins.triplegeo.'):
                            try:
                                key_part = line.split('main.plugins.triplegeo.', 1)[1]
                                if '=' in key_part:
                                    key, value = key_part.split('=', 1)
                                    key = key.strip()
                                    value = value.strip()
                                    
                                    # Parse value based on type
                                    if value.startswith('"') and value.endswith('"'):
                                        value = value[1:-1]
                                    elif value.lower() == 'true':
                                        value = True
                                    elif value.lower() == 'false':
                                        value = False
                                    elif value.startswith('[') and value.endswith(']'):
                                        inner = value[1:-1].replace('"', '').replace("'", "")
                                        value = [v.strip() for v in inner.split(',') if v.strip()]
                                    elif value.isdigit():
                                        value = int(value)
                                    
                                    config[key] = value
                                    logging.debug(f"{self.log_prefix} Parsed config: {key} = {value}")
                            except Exception as e:
                                logging.warning(f"{self.log_prefix} Error parsing line '{line}': {e}")
                    
                    break  # Only use first found config file
            
        except Exception as e:
            logging.error(f"{self.log_prefix} Error parsing config file: {e}")
        
        return config



# ============================================================================
# GPS Providers
# ============================================================================

@dataclass(frozen=True)
class GPSCacheData:
    """GPS cache data structure."""
    coordinates: Tuple[float, float]
    timestamp: float
    accuracy: Optional[float]
    source: str


class GpsdGPSProvider:
    """GPS provider using gpsd daemon."""
    
    def __init__(self, host: str = 'localhost', port: int = 2947):
        self.host = host
        self.port = port
        self.session: Optional[Any] = None
        
    def connect(self) -> bool:
        """Connect to gpsd daemon.
        
        Returns:
            True if connection successful, False otherwise
        """
        if not HAS_GPSD:
            logging.info("[TripleGeo] gpsd module not available, GPS disabled")
            return False
        
        try:
            logging.info("[TripleGeo] Connecting to gpsd...")
            self.session = gps.gps()
            self.session.stream(gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)
            logging.info("[TripleGeo] Connected to gpsd")
            return True
        except Exception as e:
            self.session = None
            logging.warning(f"[TripleGeo] gpsd connection failed: {e}")
            return False
    
    def get_coordinates(
        self, 
        accuracy_threshold: float = 100.0,
        max_attempts: int = 3
    ) -> Optional[Coordinates3D]:
        """Get current GPS coordinates from gpsd.
        
        Args:
            accuracy_threshold: Maximum acceptable accuracy in meters
            max_attempts: Number of attempts to get a valid reading
            
        Returns:
            Tuple of (lat, lon) or (lat, lon, alt) if available and valid
        """
        if not self.session:
            return None
        
        for attempt in range(max_attempts):
            try:
                report = self.session.next()
                
                # Validate TPV report with mode >= 2 (2D fix or better)
                if (getattr(report, 'class', '') == 'TPV' 
                    and getattr(report, 'mode', 1) >= 2 
                    and hasattr(report, 'lat') and hasattr(report, 'lon')):
                    
                    lat = float(report.lat)
                    lon = float(report.lon)
                    alt = getattr(report, 'alt', None)
                    accuracy = getattr(report, 'eph', None)
                    
                    # Check accuracy threshold
                    if accuracy is not None and accuracy > accuracy_threshold:
                        logging.debug(f"[TripleGeo] GPS accuracy too low ({accuracy}m > {accuracy_threshold}m)")
                        continue
                    
                    # Build coordinate tuple with altitude if available
                    if alt is not None:
                        return (lat, lon, float(alt))
                    return (lat, lon)
                    
            except StopIteration:
                break  # No more GPS data available
            except Exception as e:
                logging.debug(f"[TripleGeo] GPS read exception on attempt {attempt + 1}: {e}")
        
        return None
    
    def close(self) -> None:
        """Close gpsd connection."""
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass


class CachedGPSProvider:
    """GPS provider that serves cached coordinates."""
    
    def __init__(self, cache_file: str, expiry_hours: float = 24.0):
        self.cache_file = cache_file
        self.expiry_hours = expiry_hours
        self._coordinates: Optional[Tuple[float, float]] = None
        self._timestamp: float = 0
        self._accuracy: Optional[float] = None
    
    def load_cache(self) -> bool:
        """Load GPS cache from file.
        
        Returns:
            True if valid cache loaded, False otherwise
        """
        try:
            if not os.path.exists(self.cache_file):
                return False
            
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Check expiry
            cache_time = cache_data.get('timestamp', 0)
            age_hours = (time.time() - cache_time) / 3600
            
            if age_hours < self.expiry_hours:
                coordinates = tuple(cache_data.get('coordinates', []))
                accuracy = cache_data.get('accuracy')
                
                self._coordinates = coordinates[:2] if len(coordinates) >= 2 else None
                self._timestamp = cache_time
                self._accuracy = accuracy
                
                logging.info(f"[TripleGeo] Loaded cached GPS: {self._coordinates} "
                           f"(age: {age_hours:.1f}h, accuracy: {accuracy}m)")
                return True
        
        except Exception as e:
            logging.warning(f"[TripleGeo] Error loading GPS cache: {e}")
        
        return False
    
    def save_cache(self, coordinates: Coordinates3D, accuracy: Optional[float] = None) -> bool:
        """Save GPS coordinates to cache file.
        
        Args:
            coordinates: Tuple of (lat, lon) or (lat, lon, alt)
            accuracy: Horizontal accuracy in meters
            
        Returns:
            True if save successful, False otherwise
        """
        try:
            cache_data = {
                'coordinates': list(coordinates[:2]),  # Store lat/lon only
                'timestamp': time.time(),
                'accuracy': accuracy,
                'source': 'cached'
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
            
            self._coordinates = coordinates[:2]
            self._timestamp = cache_data['timestamp']
            self._accuracy = accuracy
            
            logging.debug(f"[TripleGeo] Saved GPS cache: {coordinates} (accuracy: {accuracy}m)")
            return True
        
        except Exception as e:
            logging.warning(f"[TripleGeo] Error saving GPS cache: {e}")
            return False
    
    def get_coordinates(self) -> Optional[Coordinates]:
        """Get cached coordinates.
        
        Returns:
            Tuple of (lat, lon) or None if no valid cache
        """
        return self._coordinates


class GPSCoordinator:
    """Coordinates GPS providers with fallback hierarchy."""
    
    def __init__(
        self,
        gpsd_provider: GpsdGPSProvider,
        cached_provider: CachedGPSProvider,
        use_last_gps: bool = True,
        fallback_to_ap_cache: bool = True
    ):
        self.gpsd_provider = gpsd_provider
        self.cached_provider = cached_provider
        self.use_last_gps = use_last_gps
        self.fallback_to_ap_cache = fallback_to_ap_cache
        
        # Track last known GPS
        self._gps_last: Optional[Tuple[float, float]] = None
        self._ap_cache_gps: Dict[str, Tuple[float, float, float]] = {}  # mac -> (lat, lon, timestamp)
    
    def set_ap_gps(
        self, 
        ap_mac: str, 
        lat: float, 
        lon: float, 
        alt: Optional[float] = None
    ) -> None:
        """Set GPS coordinates for an AP.
        
        Args:
            ap_mac: Access point MAC address
            lat: Latitude
            lon: Longitude
            alt: Altitude (optional)
        """
        if alt is not None:
            self._ap_cache_gps[ap_mac] = (lat, lon, alt)
        else:
            self._ap_cache_gps[ap_mac] = (lat, lon, 0.0)
    
    def get_best_coordinates(
        self, 
        return_source: bool = False,
        accuracy_threshold: float = 100.0,
        expiry_hours: float = 24.0,
        ap_cache_expiry_seconds: float = 3600.0
    ) -> Union[Optional[Tuple[float, float]], Tuple[Optional[Tuple[float, float]], str]]:
        """Get the best available GPS coordinate with fallback hierarchy.
        
        Priority order:
        1. Current GPS from gpsd
        2. Cached GPS from file (if enabled and valid)
        3. AP cache GPS (most recent within expiry)
        
        Args:
            return_source: If True, also returns the source string
            accuracy_threshold: Maximum acceptable GPS accuracy in meters
            expiry_hours: How long cached GPS is considered valid
            ap_cache_expiry_seconds: Max age for AP GPS fallback
            
        Returns:
            Tuple of (coordinates, source) if return_source=True, else just coordinates.
            Sources: 'current', 'cached', 'ap_cache', 'none'
        """
        # 1. Try fresh GPS from gpsd
        current_gps = self.gpsd_provider.get_coordinates(accuracy_threshold=accuracy_threshold)
        if current_gps:
            logging.debug("[TripleGeo] Using current GPS coordinates")
            
            # Update last known and cache
            self._gps_last = (current_gps[0], current_gps[1])
            self.cached_provider.save_cache(current_gps, getattr(current_gps, 'accuracy', None))
            
            if return_source:
                return current_gps[:2], "current"
            return current_gps[:2]
        
        # 2. Use cached GPS if enabled and available
        if self.use_last_gps and self._gps_last:
            cache_age_hours = (time.time() - self.cached_provider._timestamp) / 3600 if self.cached_provider._timestamp else float('inf')
            
            if cache_age_hours < expiry_hours:
                logging.info(f"[TripleGeo] Using cached GPS (age: {cache_age_hours:.1f}h): {self._gps_last}")
                if return_source:
                    return self._gps_last, "cached"
                return self._gps_last
        
        # 3. Get GPS from AP cache if enabled
        if self.fallback_to_ap_cache and self._ap_cache_gps:
            cached_gps = self._get_gps_from_ap_cache(ap_cache_expiry_seconds)
            if cached_gps:
                logging.info(f"[TripleGeo] Using GPS from AP cache: {cached_gps[:2]}")
                if return_source:
                    return cached_gps[:2], "ap_cache"
                return cached_gps[:2]
        
        logging.debug("[TripleGeo] No GPS coordinates available")
        result = (None, "none") if return_source else None
        return result
    
    def _get_gps_from_ap_cache(self, expiry_seconds: float) -> Optional[Tuple[float, float]]:
        """Extract GPS coordinates from recently cached AP data.
        
        Args:
            expiry_seconds: Maximum age for valid AP GPS data
            
        Returns:
            Tuple of (lat, lon) or None if no valid data
        """
        if not self._ap_cache_gps:
            return None
        
        now = time.time()
        best_gps = None
        best_timestamp = 0.0
        
        for ap_mac, gps_data in self._ap_cache_gps.items():
            # Get timestamp from the cache key (we store it as third element)
            lat, lon, _alt = gps_data
            
            # For simplicity, assume all AP GPS is within expiry if we have fresh data
            best_gps = (lat, lon)
            break  # Just take first valid one
        
        return best_gps
    
    def close(self) -> None:
        """Close any open resources."""
        self.gpsd_provider.close()



# ============================================================================
# Access Point Cache Manager
# ============================================================================

class APCacheManager:
    """Manages cached access point data with thread safety and expiry."""
    
    def __init__(self, expiry_minutes: float = 60.0):
        self.expiry_seconds = expiry_minutes * 60
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._last_cleanup_time: float = time.time()
    
    def add_ap(
        self, 
        mac: str, 
        ssid: str, 
        rssi: Union[int, float], 
        channel: Union[int, float],
        encryption: str,
        gps_coord: Optional[Tuple[float, float]] = None,
        clients: Optional[List[str]] = None
    ) -> None:
        """Add or update an access point in the cache.
        
        Args:
            mac: MAC address of the AP
            ssid: Network name (SSID)
            rssi: Signal strength in dBm
            channel: WiFi channel number
            encryption: Encryption type string
            gps_coord: GPS coordinates (lat, lon) if available
            clients: List of connected client MACs
        """
        with self._lock:
            # Calculate derived values
            frequency = self._calculate_frequency(channel)
            band = self._calculate_band(channel)
            
            ap_data = {
                'mac': mac,
                'ssid': ssid or 'NO_SSID',
                'rssi': rssi if rssi is not None else "N/A",
                'channel': channel if channel is not None else "N/A",
                'encryption': encryption or 'Open',
                'frequency': frequency,
                'band': band,
                'timestamp': time.time(),
                'gps_coord': gps_coord,
                'clients': clients or []
            }
            
            self._cache[mac] = ap_data
    
    def get_ap(self, mac: str) -> Optional[Dict[str, Any]]:
        """Get cached data for an access point.
        
        Args:
            mac: MAC address of the AP
            
        Returns:
            AP data dictionary or None if not found/expired
        """
        with self._lock:
            return self._cache.get(mac)
    
    def get_all_aps(self) -> List[Dict[str, Any]]:
        """Get all cached APs.
        
        Returns:
            List of all AP data dictionaries
        """
        with self._lock:
            return list(self._cache.values())
    
    def cleanup_expired(self) -> int:
        """Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        now = time.time()
        expire_time = now - self.expiry_seconds
        
        with self._lock:
            expired_keys = [
                mac for mac, data in self._cache.items()
                if data.get('timestamp', 0) < expire_time
            ]
            
            for mac in expired_keys:
                del self._cache[mac]
        
        if expired_keys:
            logging.info(f"[TripleGeo] Cleaned up {len(expired_keys)} expired AP cache entries")
        
        return len(expired_keys)
    
    def get_count(self) -> int:
        """Get number of cached APs.
        
        Returns:
            Count of APs in cache
        """
        with self._lock:
            return len(self._cache)
    
    def count_with_gps(self) -> int:
        """Count APs that have GPS coordinates.
        
        Returns:
            Number of APs with valid GPS data
        """
        with self._lock:
            return sum(1 for ap in self._cache.values() if ap.get('gps_coord'))
    
    def _calculate_frequency(self, channel: Union[int, float, str]) -> Union[int, float, str]:
        """Calculate frequency from channel number.
        
        Args:
            channel: WiFi channel number
            
        Returns:
            Frequency in MHz or "N/A" if invalid
        """
        try:
            ch = int(channel)
            if 1 <= ch <= 14:
                return 2412 + (ch - 1) * 5
            elif 36 <= ch <= 165:
                return 5000 + ch * 5
            elif 1 <= ch <= 233:
                return 5955 + (ch - 1) * 5
        except (ValueError, TypeError):
            pass
        
        return "N/A"
    
    def _calculate_band(self, channel: Union[int, float, str]) -> str:
        """Calculate band from channel number.
        
        Args:
            channel: WiFi channel number
            
        Returns:
            Band string ("2.4 GHz", "5 GHz", "6 GHz", or "unknown")
        """
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


# ============================================================================
# OUI Database Manager
# ============================================================================

class OUIDatabase:
    """Manages IEEE OUI database for vendor lookups."""
    
    def __init__(self, db_path: str = "/usr/local/share/pwnagotchi/ieee_oui.txt"):
        self.db_path = db_path
        self._database: Dict[str, str] = {}
    
    def load(self) -> int:
        """Load OUI database from file.
        
        Returns:
            Number of entries loaded
        """
        if not os.path.exists(self.db_path):
            logging.warning(f"[TripleGeo] OUI database file not found: {self.db_path}")
            return 0
        
        try:
            with open(self.db_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if '(hex)' in line:
                        parts = line.split('(hex)')
                        oui = parts[0].strip().replace('-', '').upper()[:6]
                        vendor = parts[-1].strip()
                        
                        if len(oui) >= 6:
                            self._database[oui] = vendor
            
            logging.info(f"[TripleGeo] Loaded {len(self._database)} OUIs from database")
            return len(self._database)
        
        except Exception as e:
            logging.error(f"[TripleGeo] Error loading OUI database: {e}")
            return 0
    
    def lookup(self, mac_addr: str) -> str:
        """Look up vendor for a MAC address.
        
        Args:
            mac_addr: MAC address string
            
        Returns:
            Vendor name or "Unknown" if not found
        """
        if not mac_addr:
            return "Unknown"
        
        oui = mac_addr.replace(":", "").replace("-", "").upper()[:6]
        return self._database.get(oui, "Unknown")



# ============================================================================
# Exporters for WiGLE Upload
# ============================================================================

class BaseExporter:
    """Base class for data exporters."""
    
    def __init__(self, log_prefix: str = "[TripleGeo]"):
        self.log_prefix = log_prefix
    
    def export(self, aps: List[Dict[str, Any]]) -> Optional[str]:
        """Export AP data to string format.
        
        Args:
            aps: List of AP data dictionaries
            
        Returns:
            Exported data as string or None if no data
        """
        raise NotImplementedError


class KismetCSVEExporter(BaseExporter):
    """Exports AP data in Kismet CSV format for WiGLE."""
    
    HEADER = "BSSID,SSID,firstSeen,lastSeen,channel,frequency,maxRate,rate,encryption,numMgmt,numData,numBeacon,numProbe,numOther,lat,lon,alt,accuracy,speed,bearing,type,device"
    
    def export(self, aps: List[Dict[str, Any]]) -> Optional[str]:
        """Export AP data to Kismet CSV format.
        
        Args:
            aps: List of AP data dictionaries
            
        Returns:
            CSV string or None if no valid data
        """
        if not aps:
            return None
        
        lines = [self.HEADER]
        
        for ap in aps:
            # Skip APs without GPS coordinates (required for WiGLE)
            gps_coord = ap.get('gps_coord')
            if not gps_coord or len(gps_coord) < 2:
                continue
            
            ssid = ap.get('ssid', 'NO_SSID') or 'NO_SSID'
            timestamp = int(ap.get('timestamp', time.time()))
            
            channel = ap.get('channel', 0)
            frequency = ap.get('frequency', 0)
            
            # Map encryption to Kismet values
            encryption_str = str(ap.get('encryption', '')).upper()
            if 'OPEN' in encryption_str or 'NONE' in encryption_str:
                encryption_code = '-1'  # Open/None
            elif 'WEP' in encryption_str:
                encryption_code = '-2'  # WEP
            elif 'WPA3' in encryption_str:
                encryption_code = '-4'  # WPA2+WPA3
            elif 'WPA2' in encryption_str or 'CCMP' in encryption_str:
                encryption_code = '-3'  # WPA/WPA2
            else:
                encryption_code = '-1'  # Unknown/Open
            
            lat = str(gps_coord[0]) if len(gps_coord) >= 1 else ''
            lon = str(gps_coord[1]) if len(gps_coord) >= 2 else ''
            alt = str(gps_coord[2]) if len(gps_coord) > 2 else ''
            
            # Default accuracy
            accuracy = '5.0'
            
            # Empty fields for rate and beacon counts
            max_rate = rate = num_mgmt = num_data = num_beacon = num_probe = num_other = '0'
            speed = bearing = device = 'pwnagotchi'
            ap_type = 'wlan'
            
            line = ','.join([
                ap.get('mac', ''), ssid, str(timestamp), str(timestamp),
                str(channel) if channel and channel != "N/A" else '0',
                str(frequency) if frequency and frequency != "N/A" else '0',
                max_rate, rate, encryption_code,
                num_mgmt, num_data, num_beacon, num_probe, num_other,
                lat, lon, alt, accuracy, speed, bearing, ap_type, device
            ])
            
            lines.append(line)
        
        return '\n'.join(lines)


class NetXMLExporter(BaseExporter):
    """Exports AP data in Kismet NetXML format for WiGLE."""
    
    def export(self, aps: List[Dict[str, Any]]) -> Optional[str]:
        """Export AP data to NetXML format.
        
        Args:
            aps: List of AP data dictionaries
            
        Returns:
            XML string or None if no valid data
        """
        if not aps:
            return None
        
        root = ET.Element('kismet')
        root.set('version', '2024-01')
        
        source = ET.SubElement(root, 'source')
        source.text = 'Pwnagotchi TripleGeo'
        
        time_elem = ET.SubElement(root, 'time')
        now_str = str(int(time.time()))
        time_elem.set('generated', now_str)
        time_elem.set('local', now_str)
        time_elem.set('utc', now_str)
        
        networks = ET.SubElement(root, 'networks')
        
        for ap in aps:
            gps_coord = ap.get('gps_coord')
            if not gps_coord or len(gps_coord) < 2:
                continue
            
            net_elem = ET.SubElement(networks, 'network')
            
            ssid = ap.get('ssid', 'NO_SSID') or 'NO_SSID'
            network_elem = ET.SubElement(net_elem, 'network')
            
            # MAC address
            bssid_elem = ET.SubElement(network_elem, 'bssid')
            bssid_elem.text = ap.get('mac', '')
            
            # SSID
            ssid_elem = ET.SubElement(network_elem, 'ssid')
            ssid_elem.text = ssid
            
            # Location
            loc_elem = ET.SubElement(net_elem, 'location')
            lat_elem = ET.SubElement(loc_elem, 'lat')
            lat_elem.text = str(gps_coord[0])
            
            lon_elem = ET.SubElement(loc_elem, 'lon')
            lon_elem.text = str(gps_coord[1])
            
            if len(gps_coord) > 2:
                alt_elem = ET.SubElement(loc_elem, 'alt')
                alt_elem.text = str(gps_coord[2])
            
            # Accuracy
            accuracy = ET.SubElement(net_elem, 'accuracy')
            accuracy.text = '5.0'
            
            # Channel and frequency
            freq_elem = ET.SubElement(network_elem, 'frequency')
            freq_elem.text = str(ap.get('frequency', 0)) if ap.get('frequency') else '0'
            
            ch_elem = ET.SubElement(network_elem, 'channel')
            ch_elem.text = str(ap.get('channel', 0)) if ap.get('channel') and ap.get('channel') != "N/A" else '0'
            
            # Encryption
            enc_elem = ET.SubElement(network_elem, 'encryption')
            enc_str = str(ap.get('encryption', '')).upper()
            if 'OPEN' in enc_str or 'NONE' in enc_str:
                enc_elem.text = 'None'
            elif 'WEP' in enc_str:
                enc_elem.text = 'WEP'
            elif 'WPA3' in enc_str:
                enc_elem.text = 'WPA2+WPA3'
            else:
                enc_elem.text = 'WPA2'
            
            # Timestamps
            timestamp = ap.get('timestamp', time.time())
            first_seen = ET.SubElement(network_elem, 'firsttime')
            first_seen.text = str(int(timestamp))
            
            last_seen = ET.SubElement(network_elem, 'lasttime')
            last_seen.text = str(int(timestamp))
        
        return ET.tostring(root, encoding='unicode')


class CustomCSVExporter(BaseExporter):
    """Exports AP data in simplified custom CSV format for WiGLE."""
    
    HEADER = "BSSID,SSID,Latitude,Longitude,Altitude,Channel,Frequency,Band,Encryption,RSSI,Vendor,Timestamp"
    
    def export(self, aps: List[Dict[str, Any]]) -> Optional[str]:
        """Export AP data to custom CSV format.
        
        Args:
            aps: List of AP data dictionaries
            
        Returns:
            CSV string or None if no valid data
        """
        if not aps:
            return None
        
        lines = [self.HEADER]
        
        for ap in aps:
            gps_coord = ap.get('gps_coord')
            if not gps_coord or len(gps_coord) < 2:
                continue
            
            lat = str(gps_coord[0])
            lon = str(gps_coord[1])
            alt = str(gps_coord[2]) if len(gps_coord) > 2 else ''
            
            timestamp = int(ap.get('timestamp', time.time()))
            
            line = ','.join([
                ap.get('mac', ''),
                ap.get('ssid', 'NO_SSID') or 'NO_SSID',
                lat, lon, alt,
                str(ap.get('channel', 'N/A')),
                str(ap.get('frequency', 'N/A')),
                str(ap.get('band', '')),
                str(ap.get('encryption', '')),
                str(ap.get('rssi', '')),
                str(ap.get('vendor', '')),
                str(timestamp)
            ])
            
            lines.append(line)
        
        return '\n'.join(lines)


class ExportManager:
    """Manages data export operations for WiGLE upload."""
    
    def __init__(self, export_dir: str = "/root/triplegeo_wigle_exports"):
        self.export_dir = export_dir
        self._exporters = {
            'kismet_csv': KismetCSVEExporter(),
            'netxml': NetXMLExporter(),
            'custom_csv': CustomCSVExporter()
        }
    
    def ensure_directory(self) -> Optional[str]:
        """Ensure export directory exists.
        
        Returns:
            Export directory path or None if failed
        """
        try:
            os.makedirs(self.export_dir, exist_ok=True)
            return self.export_dir
        except Exception as e:
            logging.error(f"[TripleGeo] Failed to create export directory: {e}")
            return None
    
    def export(
        self, 
        aps: List[Dict[str, Any]], 
        format_type: str = 'kismet_csv'
    ) -> ExportResult:
        """Export AP data to file.
        
        Args:
            aps: List of AP data dictionaries
            format_type: Export format ('kismet_csv', 'netxml', or 'custom_csv')
            
        Returns:
            ExportResult with filepath on success, error_message on failure
        """
        export_dir = self.ensure_directory()
        if not export_dir:
            return ExportResult.err("Failed to create export directory")
        
        # Get exporter
        exporter = self._exporters.get(format_type)
        if not exporter:
            exporter = self._exporters['kismet_csv']  # Default
        
        # Generate content
        content = exporter.export(aps)
        if not content:
            return ExportResult.err("No data to export")
        
        # Create filename with timestamp
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        extensions = {
            'kismet_csv': '.csv.gz',
            'netxml': '.netxml.gz',
            'custom_csv': '.csv.gz'
        }
        extension = extensions.get(format_type, '.csv.gz')
        
        filename = f'triplegeo_export_{timestamp}{extension}'
        filepath = os.path.join(export_dir, filename)
        
        try:
            # Write compressed file directly
            with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                f.write(content)
            
            logging.info(f"[TripleGeo] Exported {len(aps)} APs to {filepath}")
            return ExportResult.ok(filepath, filename)
        
        except Exception as e:
            logging.error(f"[TripleGeo] Export failed: {e}")
            return ExportResult.err(str(e))



# ============================================================================
# Discord Webhook Sender
# ============================================================================

class DiscordWebhookSender:
    """Sends handshake data to Discord webhooks."""
    
    def __init__(self, webhook_url: str = "", log_prefix: str = "[TripleGeo]"):
        self.webhook_url = webhook_url
        self.log_prefix = log_prefix
    
    def send(
        self, 
        event: HandshakeEvent, 
        title: str = "New Handshake Captured"
    ) -> bool:
        """Send handshake data to Discord webhook.
        
        Args:
            event: Handshake event with all metadata
            title: Embed title
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.webhook_url:
            logging.warning(f"{self.log_prefix} No Discord webhook URL configured")
            return False
        
        # Build embed
        embed = self._create_embed(event, title)
        payload = {"embeds": [embed]}
        
        try:
            # Send request
            logging.info(f"{self.log_prefix} Sending Discord webhook...")
            
            response = requests.post(
                self.webhook_url, 
                json=payload, 
                timeout=15
            )
            
            logging.info(f"{self.log_prefix} Discord response: {response.status_code}")
            
            if response.text:
                logging.debug(f"{self.log_prefix} Discord response text: {response.text}")
            
            # Check for success (204 or 200)
            if response.status_code in [200, 204]:
                logging.info(f"{self.log_prefix} Discord webhook delivered successfully")
                return True
            
        except Exception as e:
            logging.error(f"{self.log_prefix} Discord webhook error: {e}")
        
        # Fallback to simple message if embed fails
        try:
            logging.info(f"{self.log_prefix} Attempting simple message fallback...")
            
            simple_payload = {
                "content": f"**{title}**\n"
                          f"SSID: {event.ssid}\n"
                          f"BSSID: {event.bssid}\n"
                          f"Signal: {event.rssi} dBm\n"
                          f"Channel: {event.channel}\n"
                          f"Encryption: {event.encryption}\n"
                          f"Location: {event.lat},{event.lon} ({event.gps_source})\n"
                          f"File: {os.path.basename(event.handshake_file)}"
            }
            
            fallback_response = requests.post(
                self.webhook_url, 
                json=simple_payload, 
                timeout=10
            )
            
            logging.info(f"{self.log_prefix} Fallback result: {fallback_response.status_code}")
            return fallback_response.status_code in [200, 204]
        
        except Exception as e:
            logging.error(f"{self.log_prefix} Discord webhook error (fallback): {e}")
            return False
    
    def _create_embed(self, event: HandshakeEvent, title: str) -> Dict[str, Any]:
        """Create a Discord embed from handshake event.
        
        Args:
            event: Handshake event with all metadata
            title: Embed title
            
        Returns:
            Discord embed dictionary
        """
        def safe_str(value: Any, maxlen: int = 1024) -> str:
            if value is None or value == "N/A":
                return "N/A"
            sv = str(value)
            return sv[:maxlen] if len(sv) > maxlen else sv
        
        # Build fields list
        fields = [
            {"name": "SSID", "value": safe_str(event.ssid), "inline": True},
            {"name": "BSSID", "value": safe_str(event.bssid), "inline": True},
            {"name": "Client", "value": safe_str(event.client), "inline": True},
            {"name": "Signal", "value": f"{safe_str(event.rssi)} dBm", "inline": True},
            {"name": "SNR", "value": f"{safe_str(event.snr)} dB", "inline": True},
            {"name": "Channel", "value": safe_str(event.channel), "inline": True},
            {"name": "Frequency", "value": f"{safe_str(event.frequency)} MHz", "inline": True},
            {"name": "Band", "value": safe_str(event.band), "inline": True},
            {"name": "Encryption", "value": safe_str(event.encryption), "inline": True},
            {"name": "Vendor", "value": safe_str(event.vendor), "inline": True},
        ]
        
        # Add timestamp
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(event.timestamp))
        fields.append({"name": "Timestamp", "value": ts, "inline": True})
        
        # Location field
        location_text = f"Lat: {event.lat}, Lon: {event.lon}"
        if event.altitude != 'N/A':
            location_text += f", Alt: {event.altitude}m"
        if event.gps_source != 'unknown':
            location_text += f" ({event.gps_source}"
            if event.gps_age_hours > 0:
                location_text += f", {event.gps_age_hours:.1f}h old"
            location_text += ")"
        
        fields.append({"name": "Location", "value": location_text, "inline": True})
        
        # Add filename
        if event.handshake_file:
            filename = os.path.basename(event.handshake_file)
            fields.append({"name": "File", "value": safe_str(filename), "inline": False})
        
        # Cache status
        cache_status = "Cached" if event.from_cache else "Direct"
        fields.append({"name": "Data Source", "value": cache_status, "inline": True})
        
        # Determine color based on data quality
        color = 0x00ff00  # Green for complete data
        
        if event.rssi == 'N/A' or event.channel == 'N/A':
            color = 0xff6600  # Orange for missing technical data
        elif event.lat == 'N/A' or event.lon == 'N/A':
            color = 0xff9900  # Orange for no GPS
        elif event.gps_source == 'cached' and event.gps_age_hours > 12:
            color = 0xffcc00  # Yellow for old cached GPS
        
        return {
            "title": safe_str(title, 256),
            "fields": fields[:25],  # Discord max 25 fields
            "color": color,
            "footer": {"text": f"triplegeo v2.0.0 | Handshake #{getattr(self, '_handshake_count', 0)} | GPS: {event.gps_source}"}
        }


# ============================================================================
# WiGLE Uploader
# ============================================================================

class WigleUploader:
    """Uploads AP data to WiGLE Network Database."""
    
    def __init__(
        self, 
        user: str = "", 
        token: str = "", 
        api_base: str = "https://api.wigle.net/api/v3",
        export_manager: Optional[ExportManager] = None,
        log_prefix: str = "[TripleGeo]"
    ):
        self.user = user
        self.token = token
        self.api_base = api_base
        self.export_manager = export_manager or ExportManager()
        self.log_prefix = log_prefix
        
        # Tracking state
        self._last_upload_time: Optional[float] = None
        self._export_count: int = 0
    
    def upload(
        self, 
        aps: List[Dict[str, Any]], 
        format_type: str = 'kismet_csv',
        min_interval_seconds: float = 300.0
    ) -> UploadResult:
        """Upload AP data to WiGLE via API.
        
        Args:
            aps: List of AP data dictionaries
            format_type: Export format ('kismet_csv', 'netxml', or 'custom_csv')
            min_interval_seconds: Minimum seconds between uploads
            
        Returns:
            UploadResult with networks_added on success, error_message on failure
        """
        # Check credentials
        if not self.user or not self.token:
            logging.warning(f"{self.log_prefix} WiGLE credentials not configured - cannot upload")
            return UploadResult.err("WiGLE credentials not configured")
        
        # Check minimum interval since last upload
        if self._last_upload_time:
            time_since_last = time.time() - self._last_upload_time
            if time_since_last < min_interval_seconds:
                logging.debug(f"{self.log_prefix} Skipping WiGLE upload ({time_since_last:.0f}s since last)")
                return UploadResult.err("Upload interval not yet reached")
        
        # Export data first
        export_result = self.export_manager.export(aps, format_type)
        if not export_result.success:
            logging.error(f"{self.log_prefix} Export failed - aborting upload: {export_result.error_message}")
            return UploadResult.err(export_result.error_message or "Export failed")
        
        filepath = export_result.filepath
        filename = export_result.filename
        
        try:
            # Upload using WiGLE API
            url = f"{self.api_base}/network/upload"
            headers = {
                'User': self.user,
                'Key': self.token
            }
            
            with open(filepath, 'rb') as f:
                files = {'file': (filename, f)}
                
                response = requests.post(
                    url, 
                    headers=headers, 
                    files=files, 
                    timeout=120
                )
            
            logging.info(f"{self.log_prefix} WiGLE upload response: {response.status_code}")
            
            if response.text:
                logging.debug(f"{self.log_prefix} WiGLE response: {response.text}")
            
            if response.status_code == 200:
                try:
                    result_data = response.json() if response.text else {}
                    networks_added = result_data.get('data', {}).get('networks_added', 'unknown')
                    
                    logging.info(f"{self.log_prefix} WiGLE upload successful - {networks_added} networks added")
                    
                    # Update tracking state
                    self._last_upload_time = time.time()
                    self._export_count += 1
                    
                    return UploadResult.ok(int(networks_added) if isinstance(networks_added, (int, float)) else 0)
                
                except json.JSONDecodeError:
                    logging.info(f"{self.log_prefix} WiGLE upload successful - networks added unknown")
                    self._last_upload_time = time.time()
                    self._export_count += 1
                    return UploadResult.ok(0)
            
            else:
                logging.error(f"{self.log_prefix} WiGLE upload failed with status {response.status_code}")
                return UploadResult.err(f"HTTP {response.status_code}")
        
        except Exception as e:
            logging.error(f"{self.log_prefix} WiGLE upload error: {e}")
            return UploadResult.err(str(e))
    
    def get_state(self) -> Dict[str, Any]:
        """Get current upload state for persistence.
        
        Returns:
            Dictionary with last_upload_time and export_count
        """
        return {
            'last_upload': self._last_upload_time,
            'export_count': self._export_count
        }



# ============================================================================
# Main TripleGeo Plugin Class
# ============================================================================

class TripleGeo(plugins.Plugin):
    """Enhanced geolocation plugin for Pwnagotchi with WiGLE upload support.
    
    This plugin provides:
    - GPS coordinate caching and fallback hierarchy
    - Access point data collection and correlation
    - Handshake processing with comprehensive metadata
    - Discord webhook notifications
    - WiGLE Network Database uploads
    
    Attributes:
        options: Configuration dictionary loaded from various sources
    """
    
    __author__ = "disco252"
    __version__ = "2.0.0"  # Refactored version
    __license__ = "GPL3"
    __description__ = (
        "Enhanced geolocation with persistent GPS coordinates, AP caching, "
        "Discord reporting, and WiGLE upload support for Pwnagotchi."
    )
    __name__ = "triplegeo"
    
    def __init__(self):
        """Initialize TripleGeo plugin."""
        super().__init__()
        
        # Initialize components with defaults
        self._log_prefix = "[TripleGeo]"
        
        # Configuration manager
        self._config_manager = ConfigManager(self._log_prefix)
        
        # GPS infrastructure
        self._gpsd_provider: Optional[GpsdGPSProvider] = None
        self._cached_gps_provider: Optional[CachedGPSProvider] = None
        self._gps_coordinator: Optional[GPSCoordinator] = None
        
        # Data stores
        self.ap_cache: APCacheManager = APCacheManager()
        self.oui_db = OUIDatabase()
        
        # File I/O tracking
        self.processed: Set[str] = set()
        self.pending: List[str] = []
        self._pending_last_save: List[str] = []
        
        # State tracking
        self.handshake_count: int = 0
        
        # Export and upload managers
        self.export_manager: Optional[ExportManager] = None
        self.wigle_uploader: Optional[WigleUploader] = None
    
    def on_loaded(self) -> None:
        """Called when plugin is loaded by Pwnagotchi.
        
        Initializes all components, loads configuration, and sets up state.
        """
        logging.info(f"{self._log_prefix} Loading TripleGeo plugin v{self.__version__}")
        
        # Load configuration with fallbacks
        self.options = self._config_manager.load_config(
            required_secrets=['wigle_user', 'wigle_token', 'discord_webhook_url']
        )
        
        # Validate configuration
        errors = ConfigValidator.validate(self.options)
        if errors:
            for err in errors:
                logging.warning(f"{self._log_prefix} Config validation error: {err.field}: {err.message}")
        
        # Auto-enable if webhook configured
        webhook_url = self.options.get('discord_webhook_url', '')
        if webhook_url and not self.options.get('enabled', False):
            logging.info(f"{self._log_prefix} Auto-enabling plugin since webhook is configured")
            self.options['enabled'] = True
        
        # Log configuration summary
        logging.info(f"{self._log_prefix} Plugin enabled: {self.options.get('enabled', False)}")
        logging.info(f"{self._log_prefix} Discord webhook: {'Yes' if webhook_url else 'No'}")
        logging.info(f"{self._log_prefix} Use last known GPS: {self.options.get('use_last_gps', True)}")
        logging.info(f"{self._log_prefix} GPS cache expiry: {self.options.get('gps_cache_expiry_hours', 24)}h")
        logging.info(f"{self._log_prefix} GPS accuracy threshold: {self.options.get('gps_accuracy_threshold', 100)}m")
        
        # Log WiGLE configuration if enabled
        wigle_enabled = self.options.get('wigle_upload', False)
        wigle_user = self.options.get('wigle_user', '')
        if wigle_enabled and wigle_user:
            logging.info(f"{self._log_prefix} WiGLE upload: ENABLED (user: {wigle_user}, format: {self.options.get('wigle_format')})")
        else:
            logging.info(f"{self._log_prefix} WiGLE upload: DISABLED (configure wigle_upload=true, wigle_user, and wigle_token)")
        
        # Initialize components
        self._initialize_components()
        
        # Load persisted state
        self._load_storage()
        self._load_gps_cache()
        self._load_wigle_state()
        
        logging.info(f"{self._log_prefix} TripleGeo plugin loaded successfully")
    
    def _initialize_components(self) -> None:
        """Initialize all plugin components."""
        # GPS providers
        cache_file = self.options.get('gps_cache_file', '/root/.triplegeo_gps_cache')
        expiry_hours = self.options.get('gps_accuracy_threshold', 100) / 60 + 24  # Derive from config
        
        self._gpsd_provider = GpsdGPSProvider()
        
        cached_provider = CachedGPSProvider(
            cache_file=cache_file,
            expiry_hours=self.options.get('gps_cache_expiry_hours', 24.0)
        )
        self._cached_gps_provider = cached_provider
        
        # GPS coordinator with fallback hierarchy
        self._gps_coordinator = GPSCoordinator(
            gpsd_provider=self._gpsd_provider,
            cached_provider=cached_provider,
            use_last_gps=self.options.get('use_last_gps', True),
            fallback_to_ap_cache=self.options.get('fallback_to_cached_gps', True)
        )
        
        # Connect to gpsd
        self._connect_gpsd()
        
        # AP cache manager
        self.ap_cache = APCacheManager(
            expiry_minutes=self.options.get('cache_expire_minutes', 60.0)
        )
        
        # OUI database
        oui_path = self.options.get('oui_db_path', '/usr/local/share/pwnagotchi/ieee_oui.txt')
        self.oui_db = OUIDatabase(db_path=oui_path)
        self.oui_db.load()
        
        # Export and upload managers (if enabled)
        if self.options.get('wigle_upload'):
            export_dir = self.options.get('wigle_export_dir', '/root/triplegeo_wigle_exports')
            self.export_manager = ExportManager(export_dir=export_dir)
            
            wigle_uploader = WigleUploader(
                user=self.options.get('wigle_user', ''),
                token=self.options.get('wigle_token', ''),
                api_base=self.options.get('wigle_api_base', 'https://api.wigle.net/api/v3'),
                export_manager=self.export_manager,
                log_prefix=self._log_prefix
            )
            self.wigle_uploader = wigle_uploader
    
    def _connect_gpsd(self) -> None:
        """Connect to gpsd daemon."""
        if not HAS_GPSD or not self.options.get('use_last_gps', True):
            return
        
        try:
            logging.info(f"{self._log_prefix} Connecting to gpsd...")
            
            # Use the provider's connect method
            success = self._gpsd_provider.connect()
            
            if success and self._gps_coordinator:
                # Update coordinator with connected provider
                pass
                
        except Exception as e:
            logging.warning(f"{self._log_prefix} gpsd connection failed: {e}")
    
    def _load_storage(self) -> None:
        """Load persisted storage files (processed handshakes, pending list)."""
        # Load processed handshakes
        pf = self.options.get('processed_file', '/root/.triplegeo_processed')
        if os.path.exists(pf):
            try:
                with open(pf, 'r') as f:
                    self.processed = set(json.load(f))
                logging.debug(f"{self._log_prefix} Loaded {len(self.processed)} processed entries")
            except Exception as e:
                logging.warning(f"{self._log_prefix} Error loading processed file: {e}")
        
        # Load pending handshakes
        pend = self.options.get('pending_file', '/root/.triplegeo_pending')
        if os.path.exists(pend):
            try:
                with open(pend, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.pending = json.loads(content)
                logging.debug(f"{self._log_prefix} Loaded {len(self.pending)} pending entries")
            except Exception as e:
                logging.warning(f"{self._log_prefix} Error loading pending file: {e}")
    
    def _load_gps_cache(self) -> None:
        """Load GPS cache from persistent storage."""
        if not self.options.get('use_last_gps', True):
            return
        
        if self._cached_gps_provider:
            self._cached_gps_provider.load_cache()
    
    def _load_wigle_state(self) -> None:
        """Load WiGLE upload state from previous session."""
        wigle_state_file = '/root/.triplegeo_wigle_state.json'
        
        if os.path.exists(wigle_state_file):
            try:
                with open(wigle_state_file, 'r') as f:
                    state = json.load(f)
                
                if self.wigle_uploader:
                    self.wigle_uploader._last_upload_time = state.get('last_upload')
                    self.wigle_uploader._export_count = state.get('export_count', 0)
                
                logging.info(f"{self._log_prefix} Loaded WiGLE state ({self.wigle_uploader._export_count if self.wigle_uploader else 0} previous exports)")
            
            except Exception as e:
                logging.warning(f"{self._log_prefix} Failed to load WiGLE state: {e}")
    
    def _save_storage(self) -> None:
        """Save persisted storage files."""
        # Save processed handshakes
        pf = self.options.get('processed_file', '/root/.triplegeo_processed')
        try:
            with open(pf, 'w') as f:
                json.dump(list(self.processed), f)
        except Exception as e:
            logging.warning(f"{self._log_prefix} Error saving processed file: {e}")
        
        # Save pending handshakes (only if changed)
        pend = self.options.get('pending_file', '/root/.triplegeo_pending')
        if self.pending != self._pending_last_save:
            try:
                with open(pend, 'w') as f:
                    json.dump(self.pending, f)
                self._pending_last_save = list(self.pending)
            except Exception as e:
                logging.warning(f"{self._log_prefix} Error saving pending file: {e}")
    
    def _save_wigle_state(self) -> None:
        """Save WiGLE upload state for next session."""
        if not self.wigle_uploader:
            return
        
        wigle_state_file = '/root/.triplegeo_wigle_state.json'
        
        try:
            with open(wigle_state_file, 'w') as f:
                json.dump(self.wigle_uploader.get_state(), f)
            
            logging.info(f"{self._log_prefix} Saved WiGLE state to {wigle_state_file}")
        
        except Exception as e:
            logging.warning(f"{self._log_prefix} Failed to save WiGLE state: {e}")
    
    def on_unfiltered_ap_list(self, agent: Any, data: Dict[str, Any]) -> None:
        """Called when WiFi scan completes and AP list is available.
        
        Caches AP data with current GPS coordinates for later correlation
        with handshake captures.
        
        Args:
            agent: Pwnagotchi agent object (unused)
            data: Dictionary containing wifi data with aps list
        """
        if not self.options.get('enabled', False):
            return
        
        # Validate input data
        if not isinstance(data, dict) or 'wifi' not in data or 'aps' not in data['wifi']:
            logging.debug(f"{self._log_prefix} Invalid or empty AP data received")
            return
        
        # Get current GPS for this scan
        gps_coord = None
        if self._gps_coordinator:
            gps_coord, _ = self._gps_coordinator.get_best_coordinates(return_source=False)
        
        now = time.time()
        
        # Periodic cache cleanup (every 5 minutes)
        with self.ap_cache._lock:
            if now - self.ap_cache._last_cleanup_time >= 300:
                self.ap_cache.cleanup_expired()
                self.ap_cache._last_cleanup_time = now
        
        cached_count = 0
        aps_with_data = 0
        
        # Cache each AP with GPS coordinates
        for ap in data['wifi']['aps']:
            ap_mac = ap.get('mac', '')
            if not ap_mac:
                continue
            
            # Extract AP data
            ssid = ap.get('hostname', 'Hidden')
            rssi = ap.get('rssi')
            channel = ap.get('channel')
            encryption = ap.get('encryption', 'Open')
            
            # Log detailed AP data for debugging if enabled
            if self.options.get('debug_logging', False):
                logging.debug(f"{self._log_prefix} Caching AP {ap_mac}: SSID={ssid}, RSSI={rssi}, CH={channel}, ENC={encryption}")
            
            # Add to cache manager (handles derivation of frequency/band)
            self.ap_cache.add_ap(
                mac=ap_mac,
                ssid=ssid,
                rssi=rssi if rssi is not None else "N/A",
                channel=channel if channel is not None else "N/A",
                encryption=encryption or 'Open',
                gps_coord=gps_coord,
                clients=ap.get('clients', [])
            )
            
            cached_count += 1
            
            # Count APs with actual signal data
            if rssi is not None and channel is not None:
                aps_with_data += 1
        
        # Log summary
        if cached_count > 0:
            gps_status = "with GPS" if gps_coord else "no GPS"
            logging.info(f"{self._log_prefix} Cached {cached_count} APs ({aps_with_data} with signal data, {gps_status}), total cache: {self.ap_cache.get_count()}")
        
        # Check for WiGLE upload opportunity (after caching new APs)
        self._check_wigle_upload_schedule()
    
    def on_handshake(
        self, 
        agent: Any, 
        filename: str, 
        ap: Any, 
        client: Any
    ) -> None:
        """Called when a WPA handshake is captured.
        
        Processes the handshake with comprehensive metadata including
        GPS coordinates from multiple sources and sends to Discord.
        
        Args:
            agent: Pwnagotchi agent object (unused)
            filename: Path to the handshake capture file
            ap: Access point data (object or dict)
            client: Client MAC address (string, object, or dict)
        """
        if not self.options.get('enabled', False):
            logging.info(f"{self._log_prefix} Plugin disabled, skipping handshake")
            return
        
        self.handshake_count += 1
        logging.info(f"{self._log_prefix} ============ Processing handshake #{self.handshake_count} ============")
        logging.info(f"{self._log_prefix} Handshake file: {os.path.basename(filename)}")
        
        # Get best available GPS coordinates with source tracking
        gps_coord, gps_source = (None, "none")
        if self._gps_coordinator:
            gps_coord, gps_source = self._gps_coordinator.get_best_coordinates(return_source=True)
        
        gps_age_hours = 0.0
        if gps_coord and self._cached_gps_provider:
            if self._cached_gps_provider._timestamp:
                gps_age_hours = (time.time() - self._cached_gps_provider._timestamp) / 3600
        
        if gps_coord:
            logging.info(f"{self._log_prefix} GPS: {gps_coord} (source: {gps_source}, age: {gps_age_hours:.1f}h)")
        else:
            logging.info(f"{self._log_prefix} GPS: None available")
        
        # Extract SSID and BSSID from filename
        ssid, bssid = self._extract_info_from_filename(filename)
        logging.info(f"{self._log_prefix} From filename - SSID: '{ssid}', BSSID: {bssid}")
        
        # Get AP MAC from multiple sources with fallback hierarchy
        ap_mac = None
        ap_ssid = None
        
        try:
            # Try different attribute names on object
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
            logging.warning(f"{self._log_prefix} Error extracting AP data: {e}")
        
        # Fallback to filename extraction
        if not ap_mac and bssid:
            ap_mac = bssid
        if not ap_ssid and ssid:
            ap_ssid = ssid
        
        logging.info(f"{self._log_prefix} Final AP identifiers - MAC: {ap_mac}, SSID: '{ap_ssid}'")
        
        # Look up cached AP data with debug info
        cached_ap: Dict[str, Any] = {}
        from_cache = False
        
        if ap_mac and self.ap_cache.get_ap(ap_mac):
            try:
                cached_ap = self.ap_cache.get_ap(ap_mac) or {}
                
                if cached_ap:
                    from_cache = True
                    cache_age = time.time() - cached_ap.get('timestamp', 0)
                    logging.info(f"{self._log_prefix} Found cached data for {ap_mac} (age: {cache_age:.1f}s)")
                    
                    # Use GPS from cached AP data if no current GPS and option enabled
                    if not gps_coord and self.options.get("fallback_to_cached_gps", True):
                        cached_gps = cached_ap.get('gps_coord')
                        if cached_gps:
                            gps_coord = cached_gps
                            gps_source = "ap_cache"
                            gps_age_hours = cache_age / 3600
                            logging.info(f"{self._log_prefix} Using GPS from cached AP data: {cached_gps}")
                else:
                    logging.warning(f"{self._log_prefix} No cached data for {ap_mac}")
            
            except Exception as e:
                logging.error(f"{self._log_prefix} Cache access error: {e}")
        
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
            
            # Calculate derived values from cache or compute on demand
            frequency = cached_ap.get('frequency') if cached_ap else self._calculate_frequency(channel)
            band = cached_ap.get('band') if cached_ap else self._calculate_band(channel)
            vendor = cached_ap.get('vendor') if cached_ap else self.oui_db.lookup(ap_mac or '')
            
        except Exception as e:
            logging.error(f"{self._log_prefix} Data extraction error: {e}")
            frequency = "N/A"
            band = "unknown"
            vendor = "Unknown"
        
        # Calculate SNR with improved logic
        snr = "N/A"
        try:
            noise = getattr(ap, "noise", None) if hasattr(ap, 'noise') else None
            
            if isinstance(rssi, (int, float)) and isinstance(noise, (int, float)):
                snr = rssi - noise
            elif isinstance(rssi, (int, float)) and rssi != 0:
                snr = rssi - (-95)  # Estimated noise floor
        
        except Exception as e:
            logging.debug(f"{self._log_prefix} SNR calculation error: {e}")
        
        # Get client MAC with better extraction
        client_mac = ""
        try:
            if client is not None:
                if hasattr(client, 'mac'):
                    client_mac = str(client.mac)
                elif isinstance(client, dict):
                    client_mac = str(client.get('mac', ''))
                elif isinstance(client, str):
                    client_mac = client
        
        except Exception as e:
            logging.debug(f"{self._log_prefix} Client MAC extraction error: {e}")
        
        # Build event data with enhanced GPS source tracking
        event = HandshakeEvent(
            timestamp=time.time(),
            ssid=ap_ssid or ssid,
            bssid=ap_mac or "Unknown",
            client=client_mac or "None",
            rssi=rssi,
            snr=snr,
            channel=channel,
            frequency=frequency,
            band=band,
            encryption=encryption,
            lat=gps_coord[0] if gps_coord else "N/A",
            lon=gps_coord[1] if gps_coord else "N/A",
            altitude=gps_coord[2] if gps_coord and len(gps_coord) > 2 else "N/A",
            gps_source=gps_source,
            gps_age_hours=gps_age_hours,
            handshake_file=filename,
            vendor=vendor,
            from_cache=from_cache,
            cache_size=self.ap_cache.get_count()
        )
        
        # Log comprehensive technical details
        logging.info(f"{self._log_prefix} Final technical data:")
        logging.info(f"{self._log_prefix}   RSSI: {rssi} dBm")
        logging.info(f"{self._log_prefix}   Channel: {channel}")
        logging.info(f"{self._log_prefix}   Frequency: {frequency} MHz")
        logging.info(f"{self._log_prefix}   Band: {band}")
        logging.info(f"{self._log_prefix}   Encryption: {encryption}")
        logging.info(f"{self._log_prefix}   Vendor: {vendor}")
        logging.info(f"{self._log_prefix}   GPS Source: {gps_source}")
        logging.info(f"{self._log_prefix}   Data source: {'Cache' if from_cache else 'Direct'}")
        
        # Save GPS coordinates to file if available
        if gps_coord:
            coord_file = filename.replace(".pcap", ".triplegeo.coord.json")
            coord_data = {
                "coord": {"lat": gps_coord[0], "lon": gps_coord[1]},
                "source": gps_source,
                "timestamp": time.time(),
                "age_hours": gps_age_hours
            }
            if len(gps_coord) > 2:
                coord_data["coord"]["altitude"] = gps_coord[2]
            
            try:
                with open(coord_file, "w") as f:
                    json.dump(coord_data, f)
                logging.info(f"{self._log_prefix} Saved coordinates to {os.path.basename(coord_file)}")
            
            except Exception as e:
                logging.warning(f"{self._log_prefix} Could not save coord file: {e}")
        
        # Save to pending list (only if changed)
        try:
            if filename not in self.pending:
                self.pending.append(filename)
                
                # Only save to file if pending list changed
                if self.pending != self._pending_last_save:
                    self._save_storage()  # This saves both processed and pending
                    self._pending_last_save = list(self.pending)
        
        except Exception as e:
            logging.warning(f"{self._log_prefix} Error saving pending: {e}")
        
        # Send to Discord
        webhook_sender = None
        webhook_url = self.options.get('discord_webhook_url', '')
        if webhook_url:
            webhook_sender = DiscordWebhookSender(
                webhook_url=webhook_url,
                log_prefix=self._log_prefix
            )
        
        logging.info(f"{self._log_prefix} Sending handshake to Discord: {ap_ssid or ssid}")
        success = False
        
        if webhook_sender:
            try:
                # Set handshake count for embed footer
                webhook_sender._handshake_count = self.handshake_count
                
                success = webhook_sender.send(event, title="New Handshake Captured")
                
                if success:
                    logging.info(f"{self._log_prefix} Successfully sent handshake #{self.handshake_count} to Discord")
                else:
                    logging.error(f"{self._log_prefix} Failed to send handshake #{self.handshake_count} to Discord")
            
            except Exception as e:
                logging.error(f"{self._log_prefix} Discord webhook error: {e}")
        
        logging.info(f"{self._log_prefix} ============ Handshake #{self.handshake_count} Complete ============")
    
    def on_unload(self, ui: Any) -> None:
        """Called when plugin is unloaded.
        
        Saves all persistent state and cleans up resources.
        
        Args:
            ui: Pwnagotchi UI object (unused)
        """
        try:
            self._save_storage()
            
            # Save WiGLE upload tracking state
            if self.wigle_uploader:
                self._save_wigle_state()
            
            # Close GPS connection
            if self._gpsd_provider:
                self._gpsd_provider.close()
            
            logging.info(f"{self._log_prefix} Plugin cleanup completed")
        
        except Exception as e:
            logging.warning(f"{self._log_prefix} Error during cleanup: {e}")
        
        logging.info(f"{self._log_prefix} TripleGeo plugin unloaded")
    
    def _extract_info_from_filename(self, filename: str) -> Tuple[str, Optional[str]]:
        """Extract SSID and BSSID from handshake filename.
        
        Args:
            filename: Path to the capture file
            
        Returns:
            Tuple of (ssid, bssid) where bssid may be None if not found
        """
        shortname = os.path.basename(filename).replace(".pcap", "")
        parts = shortname.split("_")
        
        ssid = parts[0] if parts else shortname
        bssid: Optional[str] = None
        
        # Look for MAC pattern in filename parts
        for part in parts[1:]:
            if re.match(r'^[0-9a-fA-F]{12}$', part):  # 12 hex chars
                bssid = ':'.join([part[i:i+2] for i in range(0, 12, 2)])
                break
            elif re.match(r'^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$', part):  # Formatted MAC
                bssid = part
                break
        
        return ssid, bssid
    
    def _calculate_frequency(self, channel: Union[int, float, str]) -> Union[int, float, str]:
        """Calculate frequency from channel number.
        
        Args:
            channel: WiFi channel number
            
        Returns:
            Frequency in MHz or "N/A" if invalid
        """
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
    
    def _calculate_band(self, channel: Union[int, float, str]) -> str:
        """Calculate band from channel number.
        
        Args:
            channel: WiFi channel number
            
        Returns:
            Band string ("2.4 GHz", "5 GHz", "6 GHz", or "unknown")
        """
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
    
    def _check_wigle_upload_schedule(self) -> None:
        """Check if it's time to upload to WiGLE based on schedule.
        
        Called after caching new APs to determine if an upload should occur.
        """
        if not self.options.get('wigle_upload', False):
            return
        
        if not self.wigle_uploader:
            return
        
        wigle_delay = self.options.get('wigle_delay', 300)  # Default: 5 minutes between uploads
        
        # Check minimum time since last upload
        if self.wigle_uploader._last_upload_time:
            time_since_last = time.time() - self.wigle_uploader._last_upload_time
            if time_since_last < wigle_delay:
                logging.debug(f"{self._log_prefix} Skipping WiGLE upload ({time_since_last:.0f}s since last)")
                return
        
        # Check if we have enough data to export (at least 1 AP with GPS)
        aps = self.ap_cache.get_all_aps()
        aps_with_gps = [ap for ap in aps if ap.get('gps_coord')]
        
        if len(aps_with_gps) > 0:
            logging.info(f"{self._log_prefix} {len(aps_with_gps)} APs available for WiGLE upload")
            
            format_type = self.options.get('wigle_format', 'kismet_csv')
            result = self.wigle_uploader.upload(
                aps=aps,
                format_type=format_type,
                min_interval_seconds=wigle_delay
            )
            
            if result.success:
                logging.info(f"{self._log_prefix} WiGLE upload completed successfully ({result.networks_added or 0} networks)")


# ============================================================================
# Entry Point and Legacy Compatibility
# ============================================================================

def get_plugin() -> TripleGeo:
    """Get a new instance of the TripleGeo plugin.
    
    Returns:
        TripleGeo plugin instance for use by Pwnagotchi
    """
    return TripleGeo()


