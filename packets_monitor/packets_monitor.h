#ifndef PACKETSMONITOR_H
#define PACKETSMONITOR_H

#include <string>
#include <queue>
#include <fstream>
#include <condition_variable>
#include <unordered_map>

struct packet {
    std::string source_ip;
    std::string destination_ip;
    double total_k_bytes_bandwidth_for_ip;
};


class PacketsMonitor {
public:
    void checkNewTcpdumpDataThread();
    void processNewTcpdumpTsharkTotalBytes(std::string filePath);
    void processNewTcpdumpTsharkIPBytes(std::string filePath);
    void saveToCSV(std::string base_dir, std::string user_name);
    void loadFromCSV(std::string base_dir, std::string user_name);



    std::unordered_map<std::string, int> tcp_captured_hashmap;
    std::unordered_map<std::string, packet> packets_hashmap;
    double total_bytes_all_ips = 0;
    
    std::mutex queue_mutex;
    std::queue<std::string> tcpdump_data_queue;
    std::condition_variable queue_cond;

    std::mutex file_mutex;
};





#endif // PACKETSMONITOR_H
