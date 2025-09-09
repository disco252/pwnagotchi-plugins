

triplegeo.py 

This a plugin that determines geolocation of captured WiFi handshakes. Requires net-pos.py
It will first attempt to get coordinates via an attached GPS dongle, then it will fall back to Google's geolocation API, and finally queries the WiGLE API using BSSID data if the other options aren't available. Ensure there is internet over bluetooth tethering.

This logs all seen APs, clients on every scan with current GPS location. Reports information to Discord via webhook.

This also uploads scan data to WiGLE for mapping.

sudo apt update(never upgrade)

sudo apt install gpsd gpsd-clients

sudo apt install python3-gps(just incase, probably already there)

sudo pip3 install gpsd-py3

sudo nano /etc/default/gpsd<br>START_DAEMON="true"<br>USBAUTO="false"<br>DEVICES="/dev/ttyAMA0"<br>GPSD_OPTIONS="-n"<br>

sudo systemctl enable gpsd.service<br>
sudo systemctl start gpsd.service





Here is an example of what needs to be in config.toml:

main.plugins.triplegeo.enabled = true<br>
main.plugins.triplegeo.discord_webhook_url = "https://discord.com/api/webhookURL"<br>
main.plugins.triplegeo.google_api_key = "YOUR_GOOGLE_API_KEY"<br>
main.plugins.triplegeo.wigle_user = "YOUR_WIGLE_USERNAME"<br>
main.plugins.triplegeo.wigle_token = "YOUR_WIGLE_API_TOKEN"<br>
main.plugins.triplegeo.wigle_upload = false  # disables auto-upload, set to true to enable<br>
main.plugins.triplegeo.handshake_dir = "/home/pi/handshakes"<br>


Optional:

main.plugins.triplegeo.processed_file = "/root/.triplegeo_processed"<br>
main.plugins.triplegeo.pending_file = "/root/.triplegeo_pending" <br>
main.plugins.triplegeo.global_log_file = "/root/triplegeo_globalaplog.jsonl"<br>
main.plugins.triplegeo.wigle_delay = 2<br>
main.plugins.triplegeo.max_wigle_per_minute = 10<br>

======================================================================================================================================================================================

pcapmerger.py

This is a plugin that will automatically merge captured WiFi handshakes, pcap files by both SSID and BSSID, ensuring only valid handshakes from the same network are combined. The output is /handshakes/merged, so ensure /merged/ is a created directory. Ensure there is internet over bluetooth tethering.

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

Fastergotchi, because why not?

edit config.toml and add:

personality.recon_time = 5

personality.max_inactive_scale = 1

personality.recon_inactive_multiplier = 1

personality.hop_recon_time = 2

personality.min_recon_time = 1

personality.bored_num_epochs = 5

personality.sad_num_epochs =  10

personality.ap_ttl = 60 

personality.sta_ttl = 120

======================================================================================================================================================================================
