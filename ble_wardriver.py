import asyncio
import json
import logging
import time
import threading
import pwnagotchi.plugins as plugins
from bleak import BleakScanner
import requests

class BLEWardrive(plugins.Plugin):
    __author__ = "YourName"
    __version__ = "1.0"
    __license__ = "GPL3"
    __description__ = (
        "Bluetooth LE wardriving plugin: scans BLE adverts and posts to Discord "
        "via webhook without interrupting existing tether."
    )
    __name__ = "ble_wardrive"
    __defaults__ = {
        "enabled":             False,
        "discord_webhook_url": "",
        "scan_interval":       10,      # seconds
        "scan_duration":       5,       # seconds per scan
    }

    def __init__(self):
        super().__init__()
        self.options = dict(self.__defaults__)
        self.loop = None
        self.scanner_task = None
        self.stop_event = threading.Event()

    def on_loaded(self):
        for k, v in self.__defaults__.items():
            self.options.setdefault(k, v)
        logging.info("[BLEWardrive] Plugin loaded successfully.")
        # start the BLE scan loop in separate thread so tether remains active
        t = threading.Thread(target=self._ble_loop, daemon=True)
        t.start()

    def _ble_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.scanner_task = self.loop.create_task(self._scan_loop())
        self.loop.run_forever()

    async def _scan_loop(self):
        interval = self.options["scan_interval"]
        duration = self.options["scan_duration"]
        while not self.stop_event.is_set():
            logging.info("[BLEWardrive] Starting BLE scan")
            devices = await BleakScanner.discover(timeout=duration)
            for d in devices:
                self._report_device(d)
            await asyncio.sleep(interval)

    def _report_device(self, device):
        url = self.options.get("discord_webhook_url")
        if not url:
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        # gather advertisement data
        name = device.name or "<Unknown>"
        addr = device.address
        rssi = device.rssi
        adv_data = device.metadata.get("manufacturer_data", {})
        adv_str = "; ".join(f"{mfg}: {bytes(val).hex()}" for mfg, val in adv_data.items()) or "None"
        fields = [
            {"name": "Address", "value": addr, "inline": True},
            {"name": "Name", "value": name, "inline": True},
            {"name": "RSSI", "value": f"{rssi} dBm", "inline": True},
            {"name": "Time", "value": ts, "inline": True},
            {"name": "Manufacturer Data", "value": adv_str, "inline": False},
        ]
        payload = {
            "embeds": [
                {"title": ":satellite: BLE Device", "fields": fields, "footer": {"text": f"ble_wardrive v{self.__version__}"}}
            ]
        }
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logging.error(f"[BLEWardrive] Discord webhook error: {e}")

    def on_unload(self, ui):
        # stop scanning
        self.stop_event.set()
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        logging.info("[BLEWardrive] Plugin unloaded, stopped BLE scanning.")
