#include <iostream>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <limits>
#include "Logger/logging.hpp"
#include "NetworkInterfaceManager/NetworkInterfaceManager.hpp"
#include "PacketCaptureEngine/PacketCaptureEngine.hpp"
#include "ProtocolParser/ProtocolParser.hpp"

void clearInputStream() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main() {
    try {
        // Initialize logger
        Logger& logger = Logger::getInstance("network_analyzer.log", LogLevel::DEBUG);
        logger.log_message("Network Analyzer started", LogLevel::INFO);

        // Initialize NetworkInterfaceManager
        NetworkInterfaceManager nim;
        nim.discoverInterfaces();

        // List available interfaces and let user choose
        nim.listInterfaces();
        std::string interfaceName;
        std::cout << "Enter the name of the interface you want to use: ";
        std::cin >> interfaceName;
        clearInputStream();

        try {
            nim.selectInterface(interfaceName);
        } catch (const std::runtime_error& e) {
            std::cerr << "Error selecting interface: " << e.what() << std::endl;
            return 1;
        }

        // Initialize PacketCaptureEngine
        PacketCaptureEngine pce(nim);

        // Set a filter (optional)
        std::string filter;
        std::cout << "Enter a capture filter (e.g., 'tcp', 'udp', 'port 80') or press Enter for no filter: ";
        std::getline(std::cin, filter);
        if (!filter.empty()) {
            try {
                pce.setFilter(filter);
            } catch (const std::runtime_error& e) {
                std::cerr << "Error setting filter: " << e.what() << std::endl;
                return 1;
            }
        }

        // Start capture
        pce.startCapture();

        // Capture packets for a specified duration
        int duration;
        std::cout << "Enter capture duration in seconds: ";
        std::cin >> duration;
        clearInputStream();

        std::cout << "Capturing packets for " << duration << " seconds..." << std::endl;
        for (int i = 0; i < duration; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::cout << "." << std::flush;
        }
        std::cout << std::endl;

        // Stop capture
        pce.stopCapture();

        // Process captured packets
        ProtocolParser parser;
        struct pcap_pkthdr* header;
        const u_char* packet;
        int packetCount = 0;

        std::cout << "Processing captured packets..." << std::endl;
        while (pce.getNextPacket(&header, &packet)) {
            try {
                ProtocolParser::ParsedPacket parsedPacket = parser.parsePacket(packet, header->len);
                std::cout << "Packet " << ++packetCount << ": " 
                          << header->len << " bytes captured, "
                          << "Source IP: " << parsedPacket.ip.sourceIP << ", "
                          << "Dest IP: " << parsedPacket.ip.destIP;
                
                if (parsedPacket.isTCP) {
                    std::cout << ", TCP Ports: " << parsedPacket.transport.tcp.sourcePort 
                              << " -> " << parsedPacket.transport.tcp.destPort;
                } else {
                    std::cout << ", UDP Ports: " << parsedPacket.transport.udp.sourcePort 
                              << " -> " << parsedPacket.transport.udp.destPort;
                }
                std::cout << std::endl;

                logger.log_message("Packet processed: " + std::to_string(header->len) + " bytes", LogLevel::DEBUG);
            } catch (const std::exception& e) {
                std::cerr << "Error parsing packet: " << e.what() << std::endl;
                logger.log_message("Error parsing packet: " + std::string(e.what()), LogLevel::ERROR);
            }
        }

        std::cout << "Total packets captured and processed: " << packetCount << std::endl;
        logger.log_message("Capture completed. Total packets: " + std::to_string(packetCount), LogLevel::INFO);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        Logger::getInstance().log_message("Fatal error: " + std::string(e.what()), LogLevel::CRITICAL);
        return 1;
    }

    return 0;
}