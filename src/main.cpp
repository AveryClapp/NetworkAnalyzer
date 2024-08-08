#include <iostream>
#include <pcap.h>
#include <string>

int main(int argc, char* argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Available network interfaces:" << std::endl;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        std::cout << "- " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
    return 0;
}