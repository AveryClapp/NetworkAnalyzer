#include <iostream>
#include <pcap.h>
#include <string>
#include "./Logger/logging.hpp"
#include "./NetworkInterfaceManager/NetworkInterfaceManager.hpp"

int main() {
    Logger& logger = Logger::getInstance("log.txt", LogLevel::DEBUG, true);
    NetworkInterfaceManager manager = NetworkInterfaceManager();
    try {
        manager.discoverInterfaces();
        manager.listInterfaces();
        manager.selectInterface("lo0");
        pcap_t* handler = manager.getPcapHandle();
    } catch (const std::runtime_error& e) {
        // Log the error
        Logger::getInstance().log_message("Failed to select interface: " + std::string(e.what()), LogLevel::ERROR);
        return 1;  // Exit with error code
    }
    return 0;
}