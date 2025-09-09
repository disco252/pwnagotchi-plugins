import logging
import json
import os
import threading
import requests
import time

import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile

class NetPos(plugins.Plugin):
    __author__ = 'zenzen san, doki'
    __version__ = '2.0.5'
    __license__ = 'GPL3'
    __description__ = """Saves a json file with the access points with more signal
                         whenever a handshake is captured.
                         When internet is available the files are converted to geo locations
                         using Google Geolocation API."""

    # Default URL template; {api} will be replaced
    API_URL = 'https://www.googleapis.com/geolocation/v1/geolocate?key={api}'

    def __init__(self):
        self.skip = []
        self.ready = False
        self.lock = threading.Lock()
        self.report_path = '/root/.net_pos_saved'
        self.report = StatusFile(self.report_path, data_format='json')

    def on_loaded(self):
        # Ensure api_key is set
        if not self.options.get('api_key'):
            logging.error("NET-POS: 'api_key' not set. Can't use Google's Geolocation API.")
            return

        # Optional override of the API_URL template
        if self.options.get('api_url'):
            self.API_URL = self.options['api_url']

        # Optional override of the status file location
        if self.options.get('status_file'):
            self.report_path = self.options['status_file']
            self.report = StatusFile(self.report_path, data_format='json')

        self.ready = True
        logging.info("NET-POS: Plugin loaded successfully.")
        logging.debug(f"NET-POS: Using API URL template: {self.API_URL}")

    def on_internet_available(self, agent):
        if self.lock.locked() or not self.ready:
            return

        with self.lock:
            config = agent.config()
            display = agent.view()

            reported = self.report.data_field_or('reported', default=[])
            hs_dir = config['bettercap']['handshakes']
            all_files = os.listdir(hs_dir)
            np_files = [os.path.join(hs_dir, f) for f in all_files if f.endswith('.net-pos.json')]

            new_files = set(np_files) - set(reported) - set(self.skip)
            if not new_files:
                return

            display.set('status', f"Processing {len(new_files)} net-pos files...")
            display.update(force=True)

            for idx, path in enumerate(new_files, start=1):
                geo_path = path.replace('.net-pos.json', '.geo.json')
                if os.path.exists(geo_path):
                    reported.append(path)
                    continue

                try:
                    geo = self._get_geo_data(path)
                except Exception as e:
                    logging.error("NET-POS: %s - %s", path, e)
                    self.skip.append(path)
                    continue

                with open(geo_path, 'w') as out:
                    json.dump(geo, out)

                reported.append(path)
                self.report.update(data={'reported': reported})
                display.set('status', f"Fetched {idx}/{len(new_files)}")
                display.update(force=True)

    def on_handshake(self, agent, filename, *args):
        netpos = self._get_netpos(agent)
        if not netpos['wifiAccessPoints']:
            return

        netpos['ts'] = int(time.time())
        out_file = filename.replace('.pcap', '.net-pos.json')
        logging.debug("NET-POS: Saving to %s", out_file)

        try:
            with open(out_file, 'w') as f:
                json.dump(netpos, f)
        except OSError as e:
            logging.error("NET-POS: %s", e)

    def _get_netpos(self, agent):
        aps = agent.get_access_points()
        sorted_aps = sorted(aps, key=lambda a: a['rssi'], reverse=True)[:6]
        return {'wifiAccessPoints': [
            {'macAddress': ap['mac'], 'signalStrength': ap['rssi']}
            for ap in sorted_aps
        ]}

    def _get_geo_data(self, path, timeout=30):
        # Build request URL by replacing {api} placeholder
        geourl = self.API_URL.replace('{api}', self.options['api_key'])

        # Load the saved Wi-Fi scan data
        with open(path, 'r') as f:
            data = json.load(f)

        # Send to Google Geolocation API
        resp = requests.post(geourl, json=data, timeout=timeout)
        result = resp.json()

        # Preserve original timestamp if present
        if 'ts' in data:
            result['ts'] = data['ts']

        return result
