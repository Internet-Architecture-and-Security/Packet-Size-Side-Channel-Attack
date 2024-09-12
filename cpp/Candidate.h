#include <iostream>
#include <tins/tins.h>
#include <vector>
#include <deque>
#include <chrono>

class Candidate {
public:
    Candidate(const std::vector<uint16_t>& port_list, std::chrono::time_point<std::chrono::system_clock> time)
        : port_list(port_list), time(time) {}
            
    std::vector<uint16_t> port_list;
    std::chrono::time_point<std::chrono::system_clock> time;
};