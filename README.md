triplegeo.py
This a plugin that determines geolocation of captured WiFi handshakes.
It will first attempt to get coordinates via an attached GPS dongle, then it will fall back to Google's geolocation API, and finally queries the WiGLE API using BSSID data if the other options aren't available. Ensure there is internet over bluetooth tethering.

This script outputs SSID, BSSID, Client, Vendor, Signal, SNR, Channel, Frequency, Band, Encryption, Latitude, Longitude, Altitude (and from what source) Supported Rates, VendorTags, Timestamp, OUI lookup, Device fingerprint and the associated .pcap file name to ntfy notifications.

This also uploads scan data to WiGLE for mapping.

sudo apt update(never upgrade)

1. Install to custom plugins directory
sudo wget https://raw.githubusercontent.com/YOUR_REPO/triplegeo.py
-O /usr/local/share/pwnagotchi/custom-plugins/triplegeo.py

2. Install ntfy server (required for notifications)
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://archive.heckel.io/apt/pubkey.txt | sudo gpg --dearmor -o /etc/apt/keyrings/archive.heckel.io.gpg
echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/archive.heckel.io.gpg] https://archive.heckel.io/apt debian main" | sudo tee /etc/apt/sources.list.d/ntfy.list
sudo apt update
sudo apt install ntfy
sudo systemctl enable ntfy
sudo systemctl start ntfy

3. Install GPS support (optional)
sudo apt update
sudo apt install gpsd gpsd-clients

4. Download OUI database
sudo wget http://standards-oui.ieee.org/oui/oui.txt
-O /usr/local/share/pwnagotchi/ieee_oui.txt

5. Restart Pwnagotchi
sudo systemctl restart pwnagotchi

Ensure GPS is connected, then point GPSD at the device using (it may not be USB0, depending upon what device you're using):
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock

Here is an example of what needs to be in config.toml:

main.plugins.triplegeo.enabled = true
main.plugins.triplegeo.ntfy_server = "http://localhost:8080"
main.plugins.triplegeo.ntfy_topic = "triplegeo"
main.plugins.triplegeo.handshake_dir = "/root/handshakes"
main.plugins.triplegeo.processed_file = "/root/.triplegeo_processed"
main.plugins.triplegeo.pending_file = "/root/.triplegeo_pending"
main.plugins.triplegeo.cache_dir = "/root/.cache/triplegeo"
main.plugins.triplegeo.cache_expire_minutes = 60
main.plugins.triplegeo.cache_clean_interval = 15
main.plugins.triplegeo.global_log_file = "/root/triplegeo_globalaplog.jsonl"
main.plugins.triplegeo.google_api_key = "GOOGLE API KEY"
main.plugins.triplegeo.wigle_upload_all_aps = true
main.plugins.triplegeo.wigle_user = "TOKENIZED API NAME"
main.plugins.triplegeo.wigle_token = "TOKENIZED WIGLE API TOKEN"
main.plugins.triplegeo.wigle_upload = true
main.plugins.triplegeo.wigle_upload_all_aps = true
main.plugins.triplegeo.wigle_delay = 2
main.plugins.triplegeo.max_wigle_per_minute = 10
main.plugins.triplegeo.use_gpsd = true
main.plugins.triplegeo.gpsd_device = "/dev/ttyAMA0"
main.plugins.triplegeo.gps_retry_attempts = 5
main.plugins.triplegeo.gps_retry_delay = 1
main.plugins.triplegeo.oui_db_path = "/usr/local/share/pwnagotchi/ieee_oui.txt"
main.plugins.triplegeo.create_coord_file = true
main.plugins.triplegeo.create_webgps_file = true
main.plugins.triplegeo.webgps_compatible = true
main.plugins.triplegeo.log_handshakes = true
main.plugins.triplegeo.output_format = "json"
main.plugins.triplegeo.debug_logging = true

<img width="795" height="760" alt="Screenshot_73" src="https://github.com/user-attachments/assets/7842b107-c827-4e82-be3a-b324d7b658d7" />
======================================================================================================================================================================================

net_pos.py is based upon the original plugin, but it works. Use Google Geolocation API.

main.plugins.net-pos.enabled = true
main.plugins.net-pos.api_key = "GOOGLE API KEY HERE"
main.plugins.net-pos.loc_file = "/home/pi/.pwn/locations.json"
main.plugins.net-pos.update_interval = 300

======================================================================================================================================================================================

ble_wardrive.py will scan on its own loop, below is an interval you can set. It will report what it sees via ntfy notifications, including RSSI, name, latitude, longitude, altitude (from GPS or Google API), device fingerprinting/classification, mesh network detection, vulnerability detection (static MAC, weak names, services), anomaly detection (intervals and abnormal data), and rogue device detection. This uses IEEE OUI.txt for OUI lookup and Bluetooth Company ID database for manufacturer identification.

This does not interfere with any bluetooth tether. Note: This script in its current state does not invoke the WiFi - Google Geolocation API is incomplete, however it functions via GPSD with a GPS dongle. Please ensure in config.toml that bettercap.silence = [] does not include ble.device.new or ble.device.lost.

sudo wget https://standards-oui.ieee.org/oui/oui.txt -O /usr/local/share/pwnagotchi/ieee_oui.txt

sudo wget -O /usr/local/share/pwnagotchi/bluetooth_company_ids.json https://raw.githubusercontent.com/NordicSemiconductor/bluetooth-numbers-database/master/v1/company_identifiers.json

Configuration for ble_wardrive.py:

main.plugins.ble_wardrive.enabled = true
main.plugins.ble_wardrive.ntfy_server = "http://localhost:8080"
main.plugins.ble_wardrive.ntfy_topic = "ble_wardrive"
main.plugins.ble_wardrive.scan_interval = 10
main.plugins.ble_wardrive.scan_duration = 5
main.plugins.ble_wardrive.use_gpsd = true
main.plugins.ble_wardrive.google_api_key = "GOOGLE API KEY"
main.plugins.ble_wardrive.oui_db_path = "/usr/local/share/pwnagotchi/ieee_oui.txt"
main.plugins.ble_wardrive.bluetooth_company_db_path = "/usr/local/share/pwnagotchi/bluetooth_company_ids.json"
main.plugins.ble_wardrive.auto_download_databases = true

Ntfy notifications will log connection errors to the pwnagotchi log if bluetooth tether is unavailable, making it easy to diagnose connectivity issues.

If you are running into issues with your bluetooth tether not reconnecting upon boot (since triplegeo.py and my other ones call for bluetooth/internet connect)
sudo apt update
sudo apt install bluez bluez-tools
sudo nano /etc/systemd/system/bluetooth.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/libexec/bluetooth/bluetoothd --experimental

sudo crontab -e (add this at the end)
@reboot /usr/bin/bt-network -c INSERT:YOUR:PHONE:MAC nap &
@reboot sleep 5 && /sbin/ip link set bnep0 up
@reboot sleep 6 && /sbin/ip addr add 192.168.44.44/24 dev bnep0
@reboot sleep 7 && /sbin/ip route replace default via 192.168.44.1 dev bnep0 metric 100
