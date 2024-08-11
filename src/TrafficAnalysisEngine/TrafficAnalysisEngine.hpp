#ifndef TRAFFIC_ANALYSIS_ENGINE_HPP
#define TRAFFIC_ANALYSIS_ENGINE_HPP

#include <chrono>
#include <unordered_map>
#include <queue>
#include <array>
#include <mutex>
#include <optional>
#include "ProtocolParser/ProtocolParser.hpp"

class TrafficAnalysisEngine {
public:
    TrafficAnalysisEngine();
    void analyzePacket(const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp);
    void setReportingInterval(int seconds);
    void requestImmediateReport();

private:
    struct ConnectionStats {
        uint64_t totalBytes = 0;
        uint64_t packetCount = 0;
        double averageLatency = 0;
        double jitter = 0;
        uint32_t packetLoss = 0;
        std::array<uint32_t, 8> tosDistribution = {0};
        std::chrono::high_resolution_clock::time_point lastPacketTime;
        uint32_t lastSeqNumber = 0;
    };

    struct HistoricalData {
        uint64_t totalPackets;
        uint64_t totalBytes;
        std::chrono::high_resolution_clock::time_point timestamp;
    };

    std::unordered_map<int, int> packetsPerPort;
    std::unordered_map<std::string, int> bytesPerProtocol;
    std::unordered_map<std::string, int> topSources;
    std::unordered_map<std::string, int> topDestinations;
    std::queue<HistoricalData> historicalData;
    std::unordered_map<std::string, ConnectionStats> connectionStats;

    uint64_t totalPackets;
    uint64_t totalBytes;
    double overallBandwidthUtilization;
    std::chrono::high_resolution_clock::time_point lastReportTime;
    std::chrono::high_resolution_clock::time_point lastBandwidthCalculationTime;

    int reportingInterval;
    static const size_t MAX_HISTORICAL_DATA = 360; 

    std::mutex analysisMutex;

    void updateMetrics(const ProtocolParser::ParsedPacket& packet);
    void updatePerformanceMetrics(const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp);
    std::string generateConnectionKey(const ProtocolParser::ParsedPacket& packet);
    void updateLatencyAndJitter(const std::string& connectionKey, const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp);
    void updateBandwidthUtilization(const ProtocolParser::ParsedPacket& packet, const std::chrono::high_resolution_clock::time_point& timestamp);
    void updateQoSMetrics(const std::string& connectionKey, const ProtocolParser::ParsedPacket& packet);
    void checkForAnomalies(const ProtocolParser::ParsedPacket& packet);
    void generateReport();
    void updateHistoricalData();
    void resetIntervalMetrics();

    template<typename T>
    std::vector<std::pair<typename T::key_type, typename T::mapped_type>> 
    getTopN(const T& map, size_t n);
};

#endif // TRAFFIC_ANALYSIS_ENGINE_HPP