#ifndef PORTFINDER_H
#define PORTFINDER_H

#include <string>
#include <vector>
#include <tins/tins.h>
#include "Candidate.h"

class PortFinder {
public:
    PortFinder(const std::string& client_ip, const std::string& server_ip,
               uint16_t server_port, uint16_t start_port, uint16_t end_port,
               const std::string& send_if_name, const std::vector<std::string>& sniff_if_name,
               const std::string& client_mac, uint16_t step_size, int packet_repeat)
    : client_ip(client_ip), server_ip(server_ip), server_port(server_port), start_port(start_port),
      end_port(end_port), send_if_name(send_if_name), sniff_if_name(sniff_if_name), client_mac(client_mac), 
      step_size(step_size), packet_repeat(packet_repeat), repeat_time(2), target_frame_num(0), stop(false), 
      port_range_end(false) {}

    PortFinder(const std::vector<std::string>& sniff_if_name, const std::string& client_mac) 
    : sniff_if_name(sniff_if_name), client_mac(client_mac) {}

    PortFinder(){}

    void run();
    
    int getResult() const {
        return result;
    }

    void write_data();

private:
    std::string client_mac;
    std::string client_ip;
    std::string server_ip;
    int client_port;
    uint16_t server_port;
    uint16_t start_port;
    uint16_t current_port;
    uint16_t end_port;
    std::string send_if_name;
    std::vector<std::string> sniff_if_name;
    uint16_t step_size;
    int packet_repeat;
    int repeat_time;
    int target_frame_num;
    bool stop;
    bool port_range_end;
    std::deque<Candidate> candidate_deque;
    int send_num;
    int send_byte;
    double cost_time;
    double send_rate;
    int result;
    uint32_t maxUint32Value = std::numeric_limits<uint32_t>::max();
    uint32_t maxUint32Value_half = maxUint32Value>>1;
    uint32_t random_ack;

    void capturePackets(std::vector<Tins::Packet>& pkts_1, int sniff_if_index);

    void handle_packets(const std::vector<Tins::Packet> pkts);

    void check_port_list(const std::vector<uint16_t>& port_list);

    void find_port();

};

#endif
