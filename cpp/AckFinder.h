#ifndef ACKFINDER_H
#define ACKFINDER_H

#include <string>
#include <vector>
#include <tins/tins.h>

class AckFinder {
public:
    enum SeqNextLocation {
        SEQ_NEXT_L = -1,
        SEQ_NEXT_W = 0,
        SEQ_NEXT_R = 1
    };

    AckFinder(const std::string& client_ip, const std::string& server_ip, uint16_t client_port, uint16_t server_port,
        const std::string& send_if_name, const std::vector<std::string>& sniff_if_name, const std::string& client_mac, int repeat_num = 8)
        : client_ip(client_ip), server_ip(server_ip), client_port(client_port), server_port(server_port),  
        send_if_name(send_if_name), sniff_if_name(sniff_if_name), client_mac(client_mac), repeat_num(repeat_num), 
        sack_ack_num(0), ack_num(0), sent_seq(0), sent_seq_left_bound(-1), send_num(0), send_byte(0),
        cost_time(0), send_rate(0), result(0), frame_num(0), AMSDU_num(0), valid_frame_num(0), qos_frame_num(0), qos_frame_size(0) {}
    
    AckFinder(){}

    void run();

    uint32_t getResult() const {
        return result;
    }

    void write_data();

private:
    std::string client_mac;
    std::string client_ip;
    std::string server_ip;
    uint16_t client_port;
    uint16_t server_port;
    std::string send_if_name;
    std::vector<std::string> sniff_if_name;
    int repeat_num;
    int sack_ack_num;
    int ack_num;
    int64_t sent_seq;
    int64_t sent_seq_left_bound;
    int send_num;
    int send_byte;
    double cost_time;
    double send_rate;
    uint32_t result;
    int frame_num;
    int AMSDU_num;
    int valid_frame_num;
    int qos_frame_num;
    int qos_frame_size;
    int target_frame_num;
    uint32_t maxUint32Value = std::numeric_limits<uint32_t>::max();
    uint32_t maxUint32Value_half = maxUint32Value>>1;

    void capturePackets_1(std::vector<Tins::Packet>& pkts);

    void capturePackets_2(std::vector<Tins::Packet>& pkts);

    void handle_packets(const std::vector<Tins::Packet> pkts);

    void checkSeqList(const std::vector<uint32_t>& seq_list);

    void seqCheck(uint32_t sq, SeqNextLocation& location);

    void findSentSeq();

    void findSeqExact();

};

#endif