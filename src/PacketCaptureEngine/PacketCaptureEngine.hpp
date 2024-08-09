#ifndef PACKETCAPTUREENGINE_H
#define PACKETCAPTUREENGINE_H

#include <pcap.h>
#include "../NetworkInterfaceManager/NetworkInterfaceManager.hpp"
#include "../Logger/logging.hpp"
#include <atomic> 
#include <queue>
#include <mutex>
#include <thread>

class PacketCaptureEngine  {
    private:
        NetworkInterfaceManager& nim;
        pcap_t* pcapHandle;
        bpf_u_int32 net; 
        bpf_u_int32 mask; 
        std::queue<std::pair<struct pcap_pkthdr*, const u_char*>> packetQueue;
        std::mutex queueMutex;
        std::thread captureThread;
        std::atomic<bool> isCapturing;

        static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
        void captureLoop();

    public:
        PacketCaptureEngine(NetworkInterfaceManager& manager);
        ~PacketCaptureEngine();
        
        void setFilter(const std::string& filterExpr);
        void startCapture();
        void stopCapture();
        bool getNextPacket(struct pcap_pkthdr** header, const u_char** packet);
        bool getCaptureStatus() const;
        void cleanup();
};


#endif