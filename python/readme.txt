This is a python script to infer and hijack the victim's TCP connection based on the Wi-Fi frame size.

Dependent library: Scapy

Before running this script, you need to set the wireless card to monitor mode using something like Aircrack-ng, and then modify the configuration parameters section in main.py to set the attack parameters.
i.e., client_mac, client_ip, server_ip, server_port, send_if_name and sniff_if_name.

Note: You need to set the wireless card to the channel used by the victim to capture the victim's Wi-Fi frames.
e.g., iwconfig wlan0 channel 6

Run the script to infer the victim's TCP connection.
sudo python3 main.py