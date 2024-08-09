#include "NetworkInterfaceManager.hpp"

#include <iostream>
#include <stdexcept>


NetworkInterfaceManager::NetworkInterfaceManager() {
    // Empty, dont need to initialize anything yet   
}

NetworkInterfaceManager::~NetworkInterfaceManager() {
    // Empty, dont need to clean up anything
}

void NetworkInterfaceManager::discoverInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        exit(1);
    }

    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        NetworkInterface current_interface;
        current_interface.name = d->name;
        if (d->description) {
            current_interface.description = d->description;
        } else {
            current_interface.description = "No Description Available";
        }
        interfaces.push_back(current_interface);
    }
    pcap_freealldevs(alldevs);
}

void NetworkInterfaceManager::selectInterface(const std::string& interfaceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    auto it = std::find_if(interfaces.begin(), interfaces.end(),
                           [&](const NetworkInterface& iface) { return iface.name == interfaceName; });

    if (it == interfaces.end()) {
        throw std::runtime_error("Selected interface not found");
    }
    selectedInterface = *it;

    // Open the selected interface
    pcapHandle = pcap_open_live(selectedInterface.name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcapHandle == nullptr) {
        throw std::runtime_error("Couldn't open device " + selectedInterface.name + ": " + std::string(errbuf));
    }

}

void NetworkInterfaceManager::listInterfaces() const {
    std::cout << "Available interfaces:\n";
    for (const auto& current_interface : interfaces) {
        std::cout << current_interface.name << " - " << current_interface.description << "\n";
    }
}

pcap_t* NetworkInterfaceManager::getPcapHandle() const {
    if (pcapHandle == nullptr) {
        throw std::runtime_error("No interface selected");
    }
    return pcapHandle;
}

