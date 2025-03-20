#include "packets_monitor/packets_monitor.h"
#include "logger/logger.h"
#include <string>
#include <thread>
#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <filesystem>
#include <algorithm>


void checkNewTcpdump(PacketsMonitor *Monitor) {
    logMessage("INFO","Main::checkNewTcpdump -> Start Thread");

    Monitor->checkNewTcpdumpDataThread();
}



void periodicSave(PacketsMonitor *Monitor, std::string filename, std::string user_name) {
    logMessage("INFO","Main::periodicSave -> Start Thread");

    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
        Monitor->saveToCSV(filename, user_name);

        logMessage("INFO","Main::periodicSave -> Saved Processed Traffic");
    }
}



void periodicDelete(PacketsMonitor *Monitor) {
    logMessage("INFO","Main::periodicDelete -> Start Thread");

    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
        
        {
            std::lock_guard<std::mutex> lock(Monitor->file_mutex); // Lock while deleting
            for (auto kv : Monitor->tcp_captured_hashmap) {
                if (kv.second == 1) {
                    std::filesystem::remove(kv.first);
                }
            }
        } // Unlock after deletion

        logMessage("INFO","Main::periodicDelete -> Deleted Processed Files");
    }
}



void formatted_print(PacketsMonitor *Monitor){
    logMessage("INFO","Main::formatted_print");

    std::vector<std::pair<std::string, packet>> sorted_entries(Monitor->packets_hashmap.begin(), Monitor->packets_hashmap.end());
    
    std::sort(sorted_entries.begin(), sorted_entries.end(),
        [](const auto &a, const auto &b) {
            return a.second.total_k_bytes_bandwidth_for_ip > b.second.total_k_bytes_bandwidth_for_ip;
    });

    std::cout << std::left
    << std::setw(30) << "Source IP"
    << std::setw(30) << "Destination IP"
    << std::setw(20) << "KB Bandwidth"
    << std::setw(20) << "Total KB Bandwidth"
    << "\n";

    std::cout << std::string(100, '-') << "\n";

    int count = 0;
    for (auto kv : sorted_entries) {
        if (count >= 15) break;

        std::cout << std::left
            << std::setw(30) << kv.second.source_ip
            << std::setw(30) << kv.second.destination_ip
            << std::setw(20) << kv.second.total_k_bytes_bandwidth_for_ip
            << std::setw(20) << Monitor->total_bytes_all_ips
            << "\n";
        count++;
    }

    std::cout << std::string(100, '-') << std::endl;

    logMessage("INFO","Main::formatted_print -> Done");
}



int main(int argc, char *argv[]) {
    PacketsMonitor Monitor;
    std::string total_bytes;
    std::unordered_map<std::string, packet>* packets_hashmap;
    std::string user_name = argv[1];

    // Get previously saved traffic to accumulate on it
    Monitor.loadFromCSV("traffic_log");

    // Check new tcpdump data thread
    std::thread check_new_tcpdump_data_thread(checkNewTcpdump, &Monitor);

    // Periodic save thread
    std::thread save_thread(periodicSave, &Monitor, "traffic_log", user_name);

    // Periodic delete thread
    std::thread delete_thread(periodicDelete, &Monitor);


    logMessage("INFO","Main -> Start Main Thread");

    // Process new tcpdump data main thread
    while (true) {
        std::unique_lock<std::mutex> lock(Monitor.queue_mutex);
        Monitor.queue_cond.wait(lock, [&] { return Monitor.tcpdump_data_queue.size() > 2; });
        // Monitor.queue_cond.wait(lock);

        std::string traffic_captured_file_path = Monitor.tcpdump_data_queue.front();
        Monitor.tcpdump_data_queue.pop();
        lock.unlock();
  
        Monitor.processNewTcpdumpTsharkTotalBytes(traffic_captured_file_path);
        
        Monitor.processNewTcpdumpTsharkIPBytes(traffic_captured_file_path);

        Monitor.tcp_captured_hashmap[traffic_captured_file_path] = 1; // 1: file can be deleted
        

        // print status
        formatted_print(&Monitor);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    return 0;
}