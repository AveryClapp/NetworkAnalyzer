#include "NetworkAnalyzer.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <limits>

NetworkAnalyzer::NetworkAnalyzer() : 
    pce(nullptr), 
    logger(Logger::getInstance("network_analyzer.log", LogLevel::DEBUG)),
    isRunning(false) {
    logger.log_message("Network Analyzer initialized", LogLevel::INFO);
}

NetworkAnalyzer::~NetworkAnalyzer() {
    stopCapture();
    if (pce) {
        delete pce;
    }
}

void NetworkAnalyzer::run() {
    try {
        nim.discoverInterfaces();
        selectInterface();
        setFilter();
        startCapture();
        displayMenu();
        handleUserInput();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        logger.log_message("Fatal error: " + std::string(e.what()), LogLevel::CRITICAL);
    }
}

void NetworkAnalyzer::selectInterface() {
    nim.listInterfaces();
    std::string interfaceName;
    std::cout << "Enter the name of the interface you want to use: ";
    std::cin >> interfaceName;
    clearInputStream();

    try {
        nim.selectInterface(interfaceName);
        pce = new PacketCaptureEngine(nim);
    } catch (const std::runtime_error& e) {
        logger.log_message("Error selecting interface: " + std::string(e.what()), LogLevel::ERROR);
        throw;
    }
}

void NetworkAnalyzer::setFilter() {
    std::string filter;
    std::cout << "Enter a capture filter (e.g., 'tcp', 'udp', 'port 80') or press Enter for no filter: ";
    std::getline(std::cin, filter);
    if (!filter.empty()) {
        try {
            pce->setFilter(filter);
        } catch (const std::runtime_error& e) {
            logger.log_message("Error setting filter: " + std::string(e.what()), LogLevel::ERROR);
            throw;
        }
    }
}

void NetworkAnalyzer::startCapture() {
    if (isRunning) {
        std::cout << "Capture is already running." << std::endl;
        return;
    }

    isRunning = true;
    pce->startCapture();
    captureThread = std::thread(&NetworkAnalyzer::processPackets, this);
    std::cout << "Packet capture started." << std::endl;
}

void NetworkAnalyzer::stopCapture() {
    if (!isRunning) {
        std::cout << "No capture is currently running." << std::endl;
        return;
    }

    isRunning = false;
    pce->stopCapture();
    if (captureThread.joinable()) {
        captureThread.join();
    }
    std::cout << "Packet capture stopped." << std::endl;
}

void NetworkAnalyzer::processPackets() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int packetCount = 0;

    while (isRunning && pce->getNextPacket(&header, &packet)) {
        try {
            ProtocolParser::ParsedPacket parsedPacket = parser.parsePacket(packet, header->len);
            
            auto timestamp = std::chrono::high_resolution_clock::now();
            tae.analyzePacket(parsedPacket, timestamp);

            packetCount++;
            logger.log_message("Packet processed: " + std::to_string(header->len) + " bytes", LogLevel::DEBUG);
        } catch (const std::exception& e) {
            std::cerr << "Error parsing packet: " << e.what() << std::endl;
            logger.log_message("Error parsing packet: " + std::string(e.what()), LogLevel::ERROR);
        }
    }

    std::cout << "Total packets captured and processed: " << packetCount << std::endl;
    logger.log_message("Capture completed. Total packets: " + std::to_string(packetCount), LogLevel::INFO);
}

void NetworkAnalyzer::clearInputStream() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void NetworkAnalyzer::displayMenu() {
    std::cout << "\n--- Network Analyzer Menu ---" << std::endl;
    std::cout << "1. Start Capture" << std::endl;
    std::cout << "2. Stop Capture" << std::endl;
    std::cout << "3. Display Current Statistics" << std::endl;
    std::cout << "4. Change Reporting Interval" << std::endl;
    std::cout << "5. Exit" << std::endl;
    std::cout << "Enter your choice: ";
}

void NetworkAnalyzer::handleUserInput() {
    int choice;
    while (true) {
        displayMenu();
        std::cin >> choice;
        clearInputStream();

        switch (choice) {
            case 1:
                std::cout << "starting" << std::endl;
                startCapture();
                break;
            case 2:
                stopCapture();
                break;
            case 3:
                tae.requestImmediateReport();
                break;
            case 4:
                int interval;
                std::cout << "Enter new reporting interval in seconds: ";
                std::cin >> interval;
                clearInputStream();
                tae.setReportingInterval(interval);
                std::cout << "Reporting interval updated." << std::endl;
                break;
            case 5:
                std::cout << "stopping" << std::endl;
                stopCapture();
                std::cout << "Exiting Network Analyzer. Goodbye!" << std::endl;
                return;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }
}