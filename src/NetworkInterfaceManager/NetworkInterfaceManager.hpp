#ifndef NETWORKINTERFACEMANAGER_H
#define NETWORKINTERFACEMANAGER_H

#include <pcap.h>
#include <string>
#include <vector>

class NetworkInterface {
public:
    std::string name;
    std::string description;
};

class NetworkInterfaceManager {
    private:
        NetworkInterface selectedInterface;
        std::vector<NetworkInterface> interfaces;
        pcap_t* pcapHandle;
    public:
        NetworkInterfaceManager();

        ~NetworkInterfaceManager();

        void discoverInterfaces();

        void selectInterface(const std::string& interfaceName);
    
        void listInterfaces() const;

        pcap_t* getPcapHandle() const;
};


#endif