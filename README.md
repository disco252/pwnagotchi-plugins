triplegeo.py 

This a plugin that determines geolocation of captured WiFi handshakes.
It will first attempt to get coordinates via an attached GPS dongle, then it will fall back to Google's geolocation API, and finally queries the WiGLE API using BSSID data if the other options aren't available. Ensure there is internet over bluetooth tethering.

This script outputs SSID, BSSID, Client, Vendor, Signal, SNR, Channel, Frequency, Band, Encryption, Latitude, Longitude, Altitude(and from what source) Supported Rates, VendorTags, Timestamp, OUI lookup, Device fingerprint and the associated .pcap file name to Discord.

This also uploads scan data to WiGLE for mapping.

sudo apt update(never upgrade)

# 1. Install to custom plugins directory
sudo wget https://raw.githubusercontent.com/YOUR_REPO/triplegeo.py \
  -O /usr/local/share/pwnagotchi/custom-plugins/triplegeo.py<br>



# 2. Install GPS support (optional)
sudo apt update
sudo apt install gpsd gpsd-clients

# 3. Download OUI database (optional)
sudo wget http://standards-oui.ieee.org/oui/oui.txt \
  -O /usr/local/share/pwnagotchi/ieee_oui.txt

# 4. Restart Pwnagotchi
sudo systemctl restart pwnagotchi
Ensure GPS is connected, then point GPSD at the device using:<br>
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock


Here is an example of what needs to be in config.toml:

main.plugins.triplegeo.enabled = true<br>
main.plugins.triplegeo.mode = ["gps", "google", "wigle"]<br>
main.plugins.triplegeo.google_api_key = ""<br>
main.plugins.triplegeo.wigle_user = ""<br>
main.plugins.triplegeo.wigle_token = ""<br>
main.plugins.triplegeo.handshake_dir = "/home/pi/handshakes"<br>
main.plugins.triplegeo.processed_file = "/root/.triplegeo_processed"<br>
main.plugins.triplegeo.pending_file = "/root/.triplegeo_pending"<br>
main.plugins.triplegeo.wigle_delay = 2<br>
main.plugins.triplegeo.max_wigle_per_minute = 10<br>
main.plugins.triplegeo.wigle_upload = true<br>
main.plugins.triplegeo.global_log_file = "/root/triplegeo_globalaplog.jsonl"<br>
main.plugins.triplegeo.discord_webhook_url = "https://discord.com/api/webhooks/XXX/YYY"<br>


<img width="795" height="760" alt="Screenshot_73" src="https://github.com/user-attachments/assets/7842b107-c827-4e82-be3a-b324d7b658d7" />


======================================================================================================================================================================================

pcapmerger.py

This is a plugin that will automatically merge captured WiFi handshakes, pcap files by both SSID and BSSID, ensuring only valid handshakes from the same network are combined. The output is /handshakes/merged, so ensure /merged/ is a created directory.

Instructions:<br>
sudo apt-get update<br>
sudo apt-get install tshark wireshark-common<br>
Save pcapmerger.py in your /custom-plugins/ folder<br>
Add your custom paths:<br>
handshake_dir = "/your/path/to/handshakes"<br>
output_dir = "/your/path/to/merged"<br>

Edit your config.toml:<br>
main.plugins.pcapmerger.enabled = true 

To verify, ensure your pwnagotchi has an internet connection, then check /merged/ output directory for newly merged .pcap files. You can also use journalctl | grep pcapmerger, or pwnagotchi --debug.


======================================================================================================================================================================================

Fastergotchi, because why not?<br>
edit config.toml and add:<br>
personality.recon_time = 5<br>
personality.max_inactive_scale = 1<br>
personality.recon_inactive_multiplier = 1<br>
personality.hop_recon_time = 2<br>
personality.min_recon_time = 1<br>
personality.bored_num_epochs = 5<br>
personality.sad_num_epochs =  10<br>
personality.ap_ttl = 60 <br>
personality.sta_ttl = 120<br>

======================================================================================================================================================================================

net_pos.py is based upon the original plugin, but it works. Use Google Geolocation API. 


main.plugins.net-pos.enabled = true<br>
main.plugins.net-pos.api_key = "GOOGLE API KEY HERE"<br>
main.plugins.net-pos.loc_file = "/home/pi/.pwn/locations.json"<br>
main.plugins.net-pos.update_interval = 300<br>


======================================================================================================================================================================================

ble_wardrive.py will scan on it's own loop, below is an interval you can set. It will report what it sees on Discord, RSSI, name, latitude, longitude, altitude(from gps or google api), device fingerprinting/classification, mesh network detection, vulnerability detection (static mac, weak names, services), anomaly detection(intervals and abnormal data), rogue device detection. This uses [IEEE OUI.txt](https://standards-oui.ieee.org/oui/oui.txt) for OUI lookup. 

<img width="705" height="682" alt="Screenshot_72" src="https://github.com/user-attachments/assets/0aecd2e9-a22e-43b8-99d9-c4a1aaa4d1c8" />



This does not interfere with any bluetooth tether. Note: This script in it's current state does not invoke the WiFi - Google Geolocation API is incomplete, however it functions via GPSD with a GPS dongle. Please sure in config.toml, that beettercap.silence = [] does not incclude ble.device.new or ble.device.lost. 

sudo wget https://standards-oui.ieee.org/oui/oui.txt -O /usr/local/share/pwnagotchi/ieee_oui.txt

# If you are running into issues with your bluetooth tether not reconnecting upon boot (since triplegeo.py and my other ones call for bluetooth/internet connect)<br>
sudo apt update<br>
sudo apt install bluez bluez-tools<br>
sudo nano /etc/systemd/system/bluetooth.service.d/override.conf<br>
[Service]<br>
ExecStart=<br>
ExecStart=/usr/libexec/bluetooth/bluetoothd --experimental<br>

sudo crontab -e (add this at the end)<br>
@reboot /usr/bin/bt-network -c INSERT:YOUR:PHONE:MAC nap &<br>
@reboot sleep 5 && /sbin/ip link set bnep0 up<br>
@reboot sleep 6 && /sbin/ip addr add 192.168.44.44/24 dev bnep0<br>
@reboot sleep 7 && /sbin/ip route replace default via 192.168.44.1 dev bnep0 metric 100<br>
