#ifndef ATTACKER_H
#define ATTACKER_H

#include <string>

class Attacker {
public:
    Attacker(const std::string& client_ip,
                   const std::string& server_ip,
                   uint16_t client_port,
                   uint16_t server_port,
                   uint32_t ack_in_window,
                   uint32_t seq_in_window,
                   uint32_t seq_window_size,
                   const std::string& send_if_name)
    : client_ip(client_ip), client_port(client_port),
      server_ip(server_ip), server_port(server_port),
      ack_in_window(ack_in_window), seq_next(seq_next),
      seq_in_window(seq_in_window), seq_window_size(seq_window_size),
      send_if_name(send_if_name) {}

    Attacker(){}

    void TCP_dos();
    void TCP_inject();

private:
    std::string client_ip;
    uint16_t client_port;
    std::string server_ip;
    uint16_t server_port;
    uint32_t ack_in_window;
    uint32_t seq_next;
    uint32_t seq_in_window;
    uint32_t seq_window_size;
    std::string send_if_name;
};

#endif // ATTACKER_H
