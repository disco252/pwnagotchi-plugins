triplegeo.py is a plugin that determines geolocation of captured WiFi handshakes. 
It will first attempt to get coordinates via an attached GPS dongle, then it will fall back to Google's geolocation API, and finally queries the WiGLE API using BSSID data if the other options aren't available.

This also uploads scan data to WiGLE for mapping.

Here is an example of what needs to be in config.toml:

main.plugins.triplegeo.enabled = true
main.plugins.triplegeo.google_api_key = "YOUR_GOOGLE_API_KEY"
main.plugins.triplegeo.wigle_user = "YOUR_WIGLE_USERNAME"
main.plugins.triplegeo.wigle_token = "YOUR_WIGLE_API_TOKEN"
main.plugins.triplegeo.handshake_dir = "/home/pi/handshakes"
main.plugins.triplegeo.wigle_upload = false  # disables auto-upload, set to true to enable

