#include <iostream>
#include <pcap.h>
#include <string>
#include "./Logger/logging.hpp"
#include "./NetworkInterfaceManager/NetworkInterfaceManager.hpp"

int main() {
    Logger& logger = Logger::getInstance("log.txt", LogLevel::DEBUG, true);
    NetworkInterfaceManager manager = NetworkInterfaceManager();
    manager.discoverInterfaces();
    manager.listInterfaces();
    manager.selectInterface("en0");
    pcap_t* handler = manager.getPcapHandle();
    return 0;
}