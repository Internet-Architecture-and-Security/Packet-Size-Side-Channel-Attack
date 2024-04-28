#include <iostream>
#include <fstream>
#include <tins/tins.h>
#include <thread>

using namespace Tins;

int main(){
    std::string client_ip = "192.168.10.13";
    std::string server_ip = "43.138.73.69";
    int server_port = 22;
    int client_port = 59964;
    std::string send_if_name = "wlan0";

    int repeat_num = 4;
    uint32_t sq = 0;
    std::vector<IP> send_list;

    IP packet = IP(client_ip, server_ip) / TCP(client_port, server_port) / RawPDU("AAAA");
    TCP &tcp = packet.rfind_pdu<TCP>();
    tcp.set_flag(TCP::ACK, true);
    tcp.seq(sq);
    for (int i = 0; i < repeat_num; i++) {
        send_list.emplace_back(packet);
    }

    PacketSender sender;
    while(1){
        for(auto pkt : send_list){
            sender.send(pkt, send_if_name);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    

    return 0;
}