#include "PacketCaptureEngine.hpp"


PacketCaptureEngine::PacketCaptureEngine(NetworkInterfaceManager& manager) : nim(manager) {
    pcapHanlde = (nim.getPcapHandle);
    if (!pcapHandle) {
        throw std::runtime_error("Failed to get pcap handle from NetworkInterfaceManager");
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    const std::string& device = nim.getSelectedInterface().value_or("");
    if (device.empty()) {
        throw std::runtime_error("No network interface selected");
    }
    //Lookup IPv4 network number and mask associated with the network device's device.
    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
        Logger::logger.getInstance.log_message("Couldn't get netmask for device " + device + ": " + errbuf, LogLevel::WARNING);
        net = 0;
        mask = 0;
    } else {
        //If lookupnet is a success then we convert the IPv4 and NetMask into human readable IP addresses.
        char net_str[INET_ADDRSTRLEN];
        char mask_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = net;
        inet_ntop(AF_INET, &addr, net_str, sizeof(net_str));
        addr.s_addr = mask;
        inet_ntop(AF_INET, &addr, mask_str, sizeof(mask_str));
        Logger::logger.getInstance.log_message("Network: " + std::string(net_str) + ", Netmask: " + std::string(mask_str), LogLevel::INFO);
    }
}

PacketCaptureEngine::~PacketCaptureEngine() {
    endLoop();
}

PacketCaptureEngine::setFilter(const std::string& filter) {
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    //Get the device (should always be valid since we checked in constructor)
    const std::string& device = nim.getSelectedInterface().value_or("")

    //Compile filter
    if (pcap_compile(pcapHandle, &fp, filterExpr, 0, net) == -1) {
        throw std::runtime_error("Failed to compile filter: " + std::string(pcap_geterr(pcapHandle)));
    }
    
    //Apply filter 
    if (pcap_setfilter(pcapHandle, &fp) == -1) {
        pcap_freecode(&fp);
        throw std::runtime_error("Failed to set filter: " + std::string(pcap_geterr(pcapHandle)));
    }

    //Filter is set, free the helper filter compiler
    pcap_freecode(&fp);
    Logger::logger.getInstance.log_message("Successfully applied filter: " + filterExpr, LogLevel::INFO); 
}


void PacketCaptureEngine::startCapture() {
    //If we are already capturing packets, no need to continue
    if (isCapturing) {
        Logger::logger.getInstance.log_message("Already capturing packets", LogLevel::INFO);
        return
    }
    //Validate loop condition
    isCapturing = true;
    
    //Set capture thread to start at captureLoop function and operate
    captureThread = std::thread(&PacketCaptureEngine::captureLoop, this);
    Logger::logger.getInstance.log_message("Packet capture started", LogLevel::INFO);
}

void PacketCaptureEngine::stopCapture() {
    //If there is no capture process to stop, no need to continue
    if (!isCapturing) {
        Logger::logger.getInstance.log_message("No capture active", LogLevel::INFO);
        return
    }
    //Stop packet capture loop
    isCapturing = false;

    //Terminate captureThread
    if (captureThread.joinable()) {
        captureThread.join();
    }
    Logger:logger.getInstance.log_message("Packet capture stopped", LogLevel::INFO);
}

void PacketCaptureEngine::captureLoop() {
    //While we want to capture packets, sniff one packet at a time and call packetHandler with args of the current object casted as a u_char* 
    while (isCapturing) {
        pcap_loop(pcapHandle, 1, packetHandler, reinterpret_cast<u_char*>(this));
    }
}


void PacketCaptureEngine::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Convert userData back into a PacketCaptureEnginer
    auto pce = reinterpret_cast<PacketCaptureEngine*>(userData);

    //Lock the packet queue so we can add to it atomically
    std::lock_guard<std::mutex> lock(engine->queueMutex);
    engine->packetQueue.push(std::make_pair(pkthdr, packet));
}

//Allow for other files to access packets that are stored in the packetQueue by the pce
bool PacketCaptureEngine::getNextPacket(struct pcap_pkthdr** header, const u_char** packet) {
    //Lock the mutex so we don't mess it up by having multiple threads trying to access this
    std::lock_guard<std::mutex> lock(queueMutex);
    if (packetQueue.empty()) return false;
    
    // Assign the header and packet from the queue to change the arguments
    auto& front = packetQueue.front();
    *header = front.first;
    *packet = front.second;
    
    //Get rid of the packet from the queue
    packetQueue.pop();

    //Return true as success and also unlock the mutex
    return true;
}
