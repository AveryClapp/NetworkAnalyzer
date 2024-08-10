#include "ProtocolParser.hpp"
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

ProtocolParser::ParsedPacket ProtocolParser::parsePacket(const uint8_t* rawData, size_t dataLength) {
    ParsedPacket packet;
    size_t offset = 0;

    if (dataLength < sizeof(struct sniff_ethernet)) {
        throw std::runtime_error("Packet too short for Ethernet header");
    }

    const struct sniff_ethernet* ethHeader = reinterpret_cast<const struct sniff_ethernet*>(rawData);
    packet.ethernet = parseEthernet(ethHeader);
    offset += sizeof(struct sniff_ethernet);

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        if (dataLength - offset < sizeof(struct sniff_ip)) {
            throw std::runtime_error("Packet too short for IP header");
        }
        const struct sniff_ip* ipHeader = reinterpret_cast<const struct sniff_ip*>(rawData + offset);
        packet.ip = parseIP(ipHeader);
        offset += getIPHeaderLength(ipHeader);

        if (packet.ip.protocol == IPPROTO_TCP) {
            if (dataLength - offset < sizeof(struct sniff_tcp)) {
                throw std::runtime_error("Packet too short for TCP header");
            }
            const struct sniff_tcp* tcpHeader = reinterpret_cast<const struct sniff_tcp*>(rawData + offset);
            packet.transport.tcp = parseTCP(tcpHeader);
            packet.isTCP = true;
            offset += getTCPHeaderLength(tcpHeader);
        } 
        else if (packet.ip.protocol == IPPROTO_UDP) {
            if (dataLength - offset < sizeof(struct sniff_udp)) {
                throw std::runtime_error("Packet too short for UDP header");
            }
            const struct sniff_udp* udpHeader = reinterpret_cast<const struct sniff_udp*>(rawData + offset);
            packet.transport.udp = parseUDP(udpHeader);
            packet.isTCP = false;
            offset += sizeof(struct sniff_udp);
        }
    }

    if (offset < dataLength) {
        packet.payload.assign(rawData + offset, rawData + dataLength);
    }

    return packet;
}

ProtocolParser::EthernetHeader ProtocolParser::parseEthernet(const struct sniff_ethernet* header) {
    EthernetHeader parsed;
    parsed.sourceMac = macToString(reinterpret_cast<const uint8_t*>(header->ether_shost));
    parsed.destMac = macToString(reinterpret_cast<const uint8_t*>(header->ether_dhost));
    parsed.etherType = ntohs(header->ether_type);
    return parsed;
}

ProtocolParser::IPHeader ProtocolParser::parseIP(const struct sniff_ip* header) {
    IPHeader parsed;
    parsed.version = (header->ip_vhl >> 4) & 0x0F;
    parsed.headerLength = (header->ip_vhl & 0x0F) * 4;
    parsed.sourceIP = ipToString(&header->ip_src);
    parsed.destIP = ipToString(&header->ip_dst);
    parsed.protocol = header->ip_p;
    return parsed;
}

ProtocolParser::TCPHeader ProtocolParser::parseTCP(const struct sniff_tcp* header) {
    TCPHeader parsed;
    parsed.sourcePort = ntohs(header->th_sport);
    parsed.destPort = ntohs(header->th_dport);
    parsed.sequenceNumber = ntohl(header->th_seq);
    parsed.acknowledgmentNumber = ntohl(header->th_ack);
    parsed.dataOffset = (header->th_offx2 >> 4) & 0x0F;
    parsed.flags = header->th_flags;
    parsed.windowSize = ntohs(header->th_win);
    return parsed;
}

ProtocolParser::UDPHeader ProtocolParser::parseUDP(const struct sniff_udp* header) {
    UDPHeader parsed;
    parsed.sourcePort = ntohs(header->uh_sport);
    parsed.destPort = ntohs(header->uh_dport);
    parsed.length = ntohs(header->uh_ulen);
    parsed.checksum = ntohs(header->uh_sum);
    return parsed;
}

std::string ProtocolParser::macToString(const uint8_t* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        if (i != 5) ss << ":";
    }
    return ss.str();
}

std::string ProtocolParser::ipToString(const struct in_addr* addr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
    return std::string(ip);
}