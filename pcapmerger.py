import os
import subprocess
from collections import defaultdict

__author__ = "disco252"
__version__ = "1.3"
__license__ = "GPL3"
__description__ = (
    "PCAP merger for Pwnagotchi: merges handshake .pcap files by both SSID and BSSID. "
    "Prevents merging files with only the same SSID (to avoid mixing unrelated networks) "
    "and outputs merged results per unique AP. Designed for tidy and safe processing before hashcat conversion."
)

class Pcapmerger:
    def __init__(self, options):
        self.options = options
        self.enabled = options.get("enabled", True)
        self.handshake_dir = options.get("handshake_dir", "/home/pi/handshakes")
        self.output_dir = options.get("output_dir", "/home/pi/handshakes/merged")

    def on_internet_available(self, agent, iface):
        if not self.enabled:
            return
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.merge_pcaps()

    def get_ssid_bssid(self, pcap_path):
        cmd = [
            "tshark", "-r", pcap_path, "-Y", "wlan.ssid", "-T", "fields",
            "-e", "wlan.ssid", "-e", "wlan.bssid"
        ]
        try:
            output = subprocess.check_output(cmd, text=True, timeout=15)
            for line in output.splitlines():
                parts = line.strip().split('\t')
                if len(parts) == 2 and parts[0] and parts[1]:
                    return parts[0], parts[1]
        except Exception as e:
            print(f"[pcapmerger] Error parsing {pcap_path}: {e}")
        return None, None

    def merge_pcaps(self):
        pcaps = [
            os.path.join(self.handshake_dir, f)
            for f in os.listdir(self.handshake_dir) if f.endswith('.pcap')
        ]
        groups = defaultdict(list)
        print(f"[pcapmerger] Found {len(pcaps)} .pcap files in {self.handshake_dir}")
        for pcap in pcaps:
            ssid, bssid = self.get_ssid_bssid(pcap)
            if ssid and bssid:
                groups[(ssid, bssid)].append(pcap)
            else:
                print(f"[pcapmerger] Skipping {pcap} (SSID or BSSID not found)")
        for (ssid, bssid), files in groups.items():
            if len(files) < 2:
                continue
            safe_ssid = ssid.replace("/", "_").replace("\\", "_").replace(" ", "_")
            safe_bssid = bssid.replace(":", "-")
            out_file = os.path.join(self.output_dir, f"{safe_ssid}_{safe_bssid}_merged.pcap")
            cmd = ["mergecap", "-w", out_file] + files
            try:
                subprocess.check_call(cmd)
                print(f"[pcapmerger] Merged {len(files)} for SSID '{ssid}' BSSID {bssid} -> {out_file}")
            except Exception as e:
                print(f"[pcapmerger] Error merging group {ssid}, {bssid}: {e}")
