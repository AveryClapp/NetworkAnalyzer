#include "TrafficAnalysisEngine.hpp"
#include <iostream>
#include <algorithm>
#include <cmath>

TrafficAnalysisEngine::TrafficAnalysisEngine() 
    : totalPackets(0), totalBytes(0), overallBandwidthUtilization(0), reportingInterval(10) {
    lastReportTime = std::chrono::high_resolution_clock::now();
    lastBandwidthCalculationTime = lastReportTime;
}

void TrafficAnalysisEngine::analyzePacket(const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp) {
    std::lock_guard<std::mutex> lock(analysisMutex);

    updateMetrics(packet);
    updatePerformanceMetrics(packet, timestamp);
    checkForAnomalies(packet);

    auto now = std::chrono::high_resolution_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastReportTime).count() >= reportingInterval) {
        generateReport();
        updateHistoricalData();
        resetIntervalMetrics();
        lastReportTime = now;
    }
}

void TrafficAnalysisEngine::setReportingInterval(int seconds) {
    reportingInterval = seconds;
}

void TrafficAnalysisEngine::requestImmediateReport() {
    std::lock_guard<std::mutex> lock(analysisMutex);
    generateReport();
}

void TrafficAnalysisEngine::updateMetrics(const ProtocolParser::ParsedPacket& packet) {
    totalPackets++;
    totalBytes += packet.payload.size();

    // Update packets per port
    packetsPerPort[packet.transport.tcp.sourcePort]++;
    packetsPerPort[packet.transport.tcp.destPort]++;

    // Update bytes per protocol
    std::string protocol = packet.isTCP ? "TCP" : "UDP";
    bytesPerProtocol[protocol] += packet.payload.size();

    // Update top sources and destinations
    topSources[packet.ip.sourceIP]++;
    topDestinations[packet.ip.destIP]++;
}

void TrafficAnalysisEngine::updatePerformanceMetrics(const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp) {
    std::string connectionKey = generateConnectionKey(packet);
    updateLatencyAndJitter(connectionKey, packet, timestamp);
    updateBandwidthUtilization(packet, timestamp);
    updateQoSMetrics(connectionKey, packet);
}

std::string TrafficAnalysisEngine::generateConnectionKey(const ProtocolParser::ParsedPacket& packet) {
    return packet.ip.sourceIP + ":" + std::to_string(packet.transport.tcp.sourcePort) + "-" +
           packet.ip.destIP + ":" + std::to_string(packet.transport.tcp.destPort);
}

void TrafficAnalysisEngine::updateLatencyAndJitter(const std::string& connectionKey, const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp) {
    auto& stats = connectionStats[connectionKey];

    if (packet.isTCP && (packet.transport.tcp.flags & 0x02)) { // SYN packet
        stats.lastPacketTime = timestamp;
    } else if (packet.isTCP && (packet.transport.tcp.flags & 0x12)) { // SYN-ACK packet
        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(timestamp - stats.lastPacketTime).count() / 1000.0; // ms
        stats.averageLatency = (stats.averageLatency * stats.packetCount + latency) / (stats.packetCount + 1);
    }

    if (stats.packetCount > 0) {
        auto interPacketDelay = std::chrono::duration_cast<std::chrono::microseconds>(timestamp - stats.lastPacketTime).count() / 1000.0; // ms
        double delta = interPacketDelay - stats.jitter;
        stats.jitter += (delta - stats.jitter) / 16.0; // Exponential moving average
    }

    stats.lastPacketTime = timestamp;
    stats.packetCount++;
}

void TrafficAnalysisEngine::updateBandwidthUtilization(const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp) {
    auto timeDiff = std::chrono::duration_cast<std::chrono::seconds>(timestamp - lastBandwidthCalculationTime).count();
    if (timeDiff >= 1) {
        overallBandwidthUtilization = (totalBytes * 8.0) / timeDiff; // bits per second
        lastBandwidthCalculationTime = timestamp;
        totalBytes = 0;
    }
}

void TrafficAnalysisEngine::updateQoSMetrics(const std::string& connectionKey, const ProtocolParser::ParsedPacket& packet) {
    auto& stats = connectionStats[connectionKey];
    
    if (packet.isTCP) {
        if (stats.lastSeqNumber != 0 && packet.transport.tcp.sequenceNumber != stats.lastSeqNumber + 1) {
            stats.packetLoss++;
        }
        stats.lastSeqNumber = packet.transport.tcp.sequenceNumber;
    }
}

void TrafficAnalysisEngine::checkForAnomalies(const ProtocolParser::ParsedPacket& packet) {
  //TODO 
}

void TrafficAnalysisEngine::generateReport() {
    std::cout << "=== Traffic Analysis Report ===" << std::endl;
    std::cout << "Total Packets: " << totalPackets << std::endl;
    std::cout << "Overall Bandwidth Utilization: " << overallBandwidthUtilization / 1000000 << " Mbps" << std::endl;

    std::cout << "\nTop 5 Busy Ports:" << std::endl;
    auto topPorts = getTopN(packetsPerPort, 5);
    for (const auto& port : topPorts) {
        std::cout << "Port " << port.first << ": " << port.second << " packets" << std::endl;
    }

    std::cout << "\nProtocol Distribution:" << std::endl;
    for (const auto& protocol : bytesPerProtocol) {
        std::cout << protocol.first << ": " << protocol.second << " bytes" << std::endl;
    }

    std::cout << "\nConnection Statistics:" << std::endl;
    for (const auto& conn : connectionStats) {
        std::cout << "Connection: " << conn.first << std::endl;
        std::cout << "  Average Latency: " << conn.second.averageLatency << " ms" << std::endl;
        std::cout << "  Jitter: " << conn.second.jitter << " ms" << std::endl;
        std::cout << "  Packet Loss: " << conn.second.packetLoss << " packets" << std::endl;
    }
}

void TrafficAnalysisEngine::updateHistoricalData() {
    HistoricalData data{totalPackets, totalBytes, std::chrono::high_resolution_clock::now()};
    historicalData.push(data);
    if (historicalData.size() > MAX_HISTORICAL_DATA) {
        historicalData.pop();
    }
}

void TrafficAnalysisEngine::resetIntervalMetrics() {
    totalPackets = 0;
    totalBytes = 0;
    packetsPerPort.clear();
    bytesPerProtocol.clear();
}

template<typename T>
std::vector<std::pair<typename T::key_type, typename T::mapped_type>> 
TrafficAnalysisEngine::getTopN(const T& map, size_t n) {
    std::vector<std::pair<typename T::key_type, typename T::mapped_type>> vec(map.begin(), map.end());
    std::partial_sort(vec.begin(), vec.begin() + std::min(n, vec.size()), vec.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    vec.resize(std::min(n, vec.size()));
    return vec;
}