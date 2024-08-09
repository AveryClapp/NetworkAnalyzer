#ifndef PACKETCAPTUREENGINE_H
#define PACKETCAPTUREENGINE_H

#include <pcap.h>
#include "../NetworkInterfaceManager.hpp"
#include "../Logger/logging.hpp"
#include <atomic> 
#include <queue>
#include <mutex>
#include <thread>

class PacketCaptureEngine  {
    private:
        NetworkInterfaceManager& nim;
        Logger& logger;

        pcap_t* pcapHandle;
        bpf_u_int32 net; 
        bpf_u_int32 mask; 
        std::queue<std::pair<struct pcap_pkthdr*, const u_char*>> packetQueue;
        std::mutex queueMutex;
        std::thread captureThread;
        
        static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
        void captureLoop();
    public:
        PacketCaptureEngine(NetworkInterfaceManager& manager);
        ~PacketCaptureEngine();
        
        void setFilter(const std::stdstring& filterExpr);
        void startLoop();

        void endLoop();
};


#endif