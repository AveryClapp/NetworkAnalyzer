#include <iostream>
#include <chrono>
#include <thread>
#include "Logger/logging.hpp"
#include "NetworkInterfaceManager/NetworkInterfaceManager.hpp"
#include "PacketCaptureEngine/PacketCaptureEngine.hpp"
int main() {
    try {
        // Initialize logger
        Logger::getInstance("network_analyzer.log", LogLevel::DEBUG);

        // Initialize NetworkInterfaceManager
        NetworkInterfaceManager nim;
        nim.discoverInterfaces();

        // Select an interface (you might want to make this interactive)
        std::string interfaceName = "en0";  // Change this to a valid interface on your system
        nim.selectInterface(interfaceName);

        // Initialize PacketCaptureEngine
        PacketCaptureEngine pce(nim);

        // Set a filter (optional)
        pce.setFilter("udp"); 

        // Start capture
        pce.startCapture();

        // Capture packets for 10 seconds
        std::cout << "Capturing packets for 10 seconds..." << std::endl;
        for (int i = 0; i < 10; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::cout << "." << std::flush;
        }
        std::cout << std::endl;

        // Stop capture
        pce.stopCapture();

        // Process captured packets
        struct pcap_pkthdr* header;
        const u_char* packet;
        int packetCount = 0;
        while (pce.getNextPacket(&header, &packet)) {
            std::cout << "Packet " << ++packetCount << ": " << header->len << " bytes captured" << std::endl;
        }

        std::cout << "Total packets captured: " << packetCount << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}