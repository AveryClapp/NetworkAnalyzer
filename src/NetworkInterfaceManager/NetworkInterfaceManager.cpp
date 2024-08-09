#include "NetworkInterfaceManager.hpp"

#include <iostream>
#include <stdexcept>


NetworkInterfaceManager::NetworkInterfaceManager() : pcapHandle(nullptr) {}

NetworkInterfaceManager::~NetworkInterfaceManager() {
    if (pcapHandle != nullptr) {
        pcap_close(pcapHandle);
    }
}

void NetworkInterfaceManager::discoverInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    //Find all devices on the current machine
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        throw std::runtime_error("Error in pcap_findalldevs: " + std::string(errbuf));
    }

    //For all available devices, create an instance of Network Interface and append it to the interface vector
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

//Allow the user to select an interface given the string
void NetworkInterfaceManager::selectInterface(const std::string& interfaceName) {
    //Check if there is already a selected interface
    if (pcapHandle != nullptr) {
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
        std::cout << "Closing previously selected interface: " << selectedInterface->name << std::endl;
    }

    //Find the user inputted interfaceName in the list of interfaces
    char errbuf[PCAP_ERRBUF_SIZE];
    auto it = std::find_if(interfaces.begin(), interfaces.end(),
                           [&](const NetworkInterface& iface) { return iface.name == interfaceName; });

    //If the interface isn't valid throw a runtime error
    if (it == interfaces.end()) {
        throw std::runtime_error("Selected interface not found");
    }
    selectedInterface = *it;

    //Open the selected interface
    pcapHandle = pcap_open_live(selectedInterface->name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcapHandle == nullptr) {
        throw std::runtime_error("Couldn't open device " + selectedInterface->name + ": " + std::string(errbuf));
    }
    //Store the link type in a class variable if pcap is opened successfully
    linkType = pcap_datalink(pcapHandle);
    if (linkType != DLT_EN10MB) {
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
        linkType = std::nullopt;
        selectedInterface = std::nullopt;
        throw std::runtime_error("Device " + interfaceName + " is not supported at this time. Please retry with a different interface.");
    } 
    std::cout << "Successfully selected and opened interface: " << selectedInterface->name << std::endl;
}

//Lists all available interfaces on your device
void NetworkInterfaceManager::listInterfaces() const {
    std::cout << "Available interfaces:\n";
    for (const auto& current_interface : interfaces) {
        std::cout << current_interface.name << " - " << current_interface.description << std::endl;
    }
}

//Return the currently selected pcapHandle
pcap_t* NetworkInterfaceManager::getPcapHandle() {
    if (pcapHandle == nullptr) {
        throw std::runtime_error("No interface selected");
    }
    return pcapHandle;
}

//Get the link typing of the current interface
std::optional<int> NetworkInterfaceManager::getDataLinkType() const {
    return linkType;
}

//Return the selectedInterface if there is one, else return nothing
std::optional<std::string> NetworkInterfaceManager::getSelectedInterface() const {
    return selectedInterface->name;
}