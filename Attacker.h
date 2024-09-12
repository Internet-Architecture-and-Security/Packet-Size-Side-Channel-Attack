#ifndef ATTACKER_H
#define ATTACKER_H

#include <string>

class Attacker {
public:
    Attacker(const std::string& client_ip,
                   const std::string& server_ip,
                   uint16_t client_port,
                   uint16_t server_port,
                   uint32_t seq_in_window,
                   uint32_t ack_in_window,
                   uint32_t seq_window_size,
                   u_int32_t ack_window_size,
                   const std::string& send_if_name)
    : client_ip(client_ip), server_ip(server_ip),
      client_port(client_port), server_port(server_port),
      seq_in_window(seq_in_window), ack_in_window(ack_in_window),
      seq_window_size(seq_window_size), ack_window_size(ack_window_size),
      send_if_name(send_if_name) {}

    Attacker(){}

    void TCP_dos();
    void TCP_inject();

private:
    std::string client_ip;
    uint16_t client_port;
    std::string server_ip;
    uint16_t server_port;
    int64_t seq_in_window;
    int64_t ack_in_window;
    uint32_t seq_window_size;
    uint32_t ack_window_size;
    std::string send_if_name;
};

#endif // ATTACKER_H
