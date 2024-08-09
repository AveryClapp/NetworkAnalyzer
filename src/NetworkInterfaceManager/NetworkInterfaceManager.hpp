#ifndef NETWORKINTERFACEMANAGER_H
#define NETWORKINTERFACEMANAGER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <optional> 

class NetworkInterface {
public:
    std::string name;
    std::string description;
};

class NetworkInterfaceManager {
    private:
        std::optional<NetworkInterface> selectedInterface;
        std::vector<NetworkInterface> interfaces;
        pcap_t* pcapHandle;
        std::optional<int> linkType;

    public:
        NetworkInterfaceManager();

        ~NetworkInterfaceManager();

        void discoverInterfaces();

        void selectInterface(const std::string& interfaceName);
    
        void listInterfaces() const;

        pcap_t* getPcapHandle();
        
        std::optional<int> getDataLinkType() const;

        std::optional<std::string> getSelectedInterface() const;
};


#endif