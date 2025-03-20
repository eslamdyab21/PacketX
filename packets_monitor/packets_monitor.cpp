#include <filesystem>
#include <unordered_map>
#include <array>
#include <iostream>
#include <algorithm>
#include <thread>
#include "packets_monitor.h"
#include "../logger/logger.h"



void PacketsMonitor::checkNewTcpdumpDataThread() {
    logMessage("INFO","PacketsMonitor::checkNewTcpdumpDataThread");

    std::string path = ".tcpdump";
    std::uintmax_t file_size;

    while (true) {
        {
            std::lock_guard<std::mutex> lock(file_mutex); // Prevent checking while deleting
            for (const auto & entry : std::filesystem::directory_iterator(path)){
                if (entry.is_regular_file() && entry.path().extension() == ".pcap"){

                    file_size = std::filesystem::file_size(entry.path());
                    
                    // New tcpdump file
                    if ((tcp_captured_hashmap.count(entry.path()) == 0) && file_size > 0){
                        logMessage("INFO","PacketsMonitor::checkNewTcpdumpDataThread -> Found A New File");

                        tcp_captured_hashmap[entry.path()] = 0;
                        
                        {
                            std::lock_guard<std::mutex> lock(queue_mutex);
                            tcpdump_data_queue.push(entry.path().string());
                        }
                        queue_cond.notify_one();
                        logMessage("INFO","PacketsMonitor::checkNewTcpdumpDataThread -> Pushed New File To Queue");
        
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } // Unlock
    }
}



void PacketsMonitor::processNewTcpdumpTsharkTotalBytes(std::string filePath) {
    logMessage("INFO","PacketsMonitor::processNewTcpdumpTsharkTotalBytes -> " + filePath);

    std::array<char, 512> buffer;
    std::string total_bytes;

    std::string cmd = "tshark -r " + filePath + " -qz io,phs | grep 'eth' | grep 'bytes' | cut -d':' -f3";

    FILE* pipe = popen(cmd.c_str(), "r");

    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        total_bytes += buffer.data();
    }

    if (!total_bytes.empty())
        total_bytes_all_ips += (std::stod(total_bytes)) / 1024; 
    
    pclose(pipe);
    logMessage("INFO","PacketsMonitor::processNewTcpdumpTsharkTotalBytes -> Executed Tshark Total Bytes CMD");
}


void PacketsMonitor::processNewTcpdumpTsharkIPBytes(std::string filePath) {
    logMessage("INFO","PacketsMonitor::processNewTcpdumpTsharkIPBytes -> " + filePath);

    std::array<char, 1024> buffer;
    std::string temp;
    std::string ip1, ip2, key;
    double total_bytes;
    
    std::string cmd = "tshark -r " + filePath + " -q -z conv,ip | grep '<->' | sed 's/[[:space:]]\\+/ /g'";
    
    FILE* pipe = popen(cmd.c_str(), "r");
    
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        std::istringstream iss(buffer.data());

        // Extract IPs
        std::getline(iss, ip1, ' ');  // Read first IP
        std::getline(iss, temp, ' '); // Read "<->"
        std::getline(iss, ip2, ' ');  // Read second IP

        // Persist key arrangement
        // Treat (172.29.0.1, 172.29.1.167) same as (172.29.1.167, 172.29.0.1) in the hashmap
        if (ip1 < ip2){
            temp = ip1;
            ip1 = ip2;
            ip2 = temp; 
        }
        key = ip1 + "-" + ip2;


        // Skip
        for (int i=0; i < 7; i++)
            std::getline(iss, temp, ' ');
        
        std::getline(iss, temp, ' ');
        total_bytes = std::stoi(temp); // Read total bytes

        std::getline(iss, temp, ' '); // Read Bytes or k bytes
        if (temp == "bytes")
            total_bytes = total_bytes / 1024;
        
        if (packets_hashmap.count(key) == 0){
            packets_hashmap[key].source_ip = ip1;
            packets_hashmap[key].destination_ip = ip2;
            packets_hashmap[key].total_k_bytes_bandwidth_for_ip = total_bytes;
        }
        else 
            packets_hashmap[key].total_k_bytes_bandwidth_for_ip += total_bytes;
        
    }

    pclose(pipe);
    logMessage("INFO","PacketsMonitor::processNewTcpdumpTsharkIPBytes -> Executed Tshark Total Bytes/IP CMD");
}



void PacketsMonitor::saveToCSV(std::string base_dir, std::string user_name) {
    logMessage("INFO","PacketsMonitor::saveToCSV");
    
    // Get current time
    char timeStr[20];
    char dateStr[20];
    std::time_t now = std::time(nullptr);
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M", std::localtime(&now));
    std::strftime(dateStr, sizeof(dateStr), "%Y-%m-%d", std::localtime(&now));

    std::string filename = base_dir + "/" + dateStr + ".csv";
    
    // Create directory if it doesn’t exist
    try {
        std::filesystem::create_directories(base_dir);
    } 
    catch (const std::filesystem::filesystem_error& e) {
        logMessage("ERROR", "PacketsMonitor::saveToCSV -> Failed to create directory: " + std::string(e.what()));
        return;
    }

    bool file_exists = std::filesystem::exists(filename);

    std::ofstream file(filename, std::ios::app); // append mode

    if (!file) {
        logMessage("INFO","PacketsMonitor::saveToCSV -> Error opening file for writing!");
        return;
    }

    

    // Header
    if (!file_exists)
        file << "User,Time Stamp,Source IP,Destination IP,KB Bandwidth,Total KB Bandwidth\n";

    
    // Data
    for (const auto& kv : packets_hashmap) {
        file << user_name << "," 
             << timeStr << "," 
             << kv.second.source_ip << "," 
             << kv.second.destination_ip << ","
             << kv.second.total_k_bytes_bandwidth_for_ip << ","
             << total_bytes_all_ips << "\n";
    }

    file.close();

    // clear previous minute packets data
    packets_hashmap.clear(); 
    total_bytes_all_ips = 0;

    logMessage("INFO","PacketsMonitor::saveToCSV -> " + filename + " Done");
}




void PacketsMonitor::loadFromCSV(std::string base_dir) {
    logMessage("INFO","PacketsMonitor::loadFromCSV");

    // Get current time
    char dateStr[20];
    std::time_t now = std::time(nullptr);
    std::strftime(dateStr, sizeof(dateStr), "%Y-%m-%d", std::localtime(&now));

    std::string filename = base_dir + "/" + dateStr + ".csv";

    std::ifstream file(filename);
    bool firstLine = true;
    std::string line;


    if (!file && !std::filesystem::exists(filename)) {
        logMessage("INFO","PacketsMonitor::loadFromCSV -> Can't Open File");
        return;
    }

    while (std::getline(file, line)) {
        if (firstLine) { 
            firstLine = false; // Skip header line
            continue;
        }

        std::istringstream iss(line);
        packet p;
        std::string bandwidth, total_bandwidth;

        std::getline(iss, p.source_ip, ','); // skip timestamp
        std::getline(iss, p.source_ip, ',');
        std::getline(iss, p.destination_ip, ',');
        std::getline(iss, bandwidth, ',');
        std::getline(iss, total_bandwidth, ',');

        p.total_k_bytes_bandwidth_for_ip = std::stod(bandwidth);
        std::string key = p.source_ip + "-" + p.destination_ip;
        packets_hashmap[key] = p;
        total_bytes_all_ips = std::stod(total_bandwidth);
    }

    file.close();

    logMessage("INFO","PacketsMonitor::loadFromCSV -> Done");
}