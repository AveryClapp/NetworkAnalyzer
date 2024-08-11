#ifndef NETWORK_ANALYZER_HPP
#define NETWORK_ANALYZER_HPP

#include "Logger/logging.hpp"
#include "NetworkInterfaceManager/NetworkInterfaceManager.hpp"
#include "PacketCaptureEngine/PacketCaptureEngine.hpp"
#include "ProtocolParser/ProtocolParser.hpp"
#include "TrafficAnalysisEngine/TrafficAnalysisEngine.hpp"
#include <atomic>
#include <thread>

class NetworkAnalyzer {
public:
    NetworkAnalyzer();
    ~NetworkAnalyzer();
    void run();

private:
    NetworkInterfaceManager nim;
    PacketCaptureEngine* pce;
    ProtocolParser parser;
    TrafficAnalysisEngine tae;
    Logger& logger;
    std::atomic<bool> isRunning;
    std::thread captureThread;

    void selectInterface();
    void setFilter();
    void startCapture();
    void stopCapture();
    void processPackets();
    void clearInputStream();
    void displayMenu();
    void handleUserInput();
};

#endif 