#ifndef PROTOCOLPARSER_HPP
#define PROTOCOLPARSER_HPP

#include <vector>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
class ProtocolParser {  
    
    public:
         // Ethernet header
        struct sniff_ethernet {
            u_char ether_dhost[6];
            u_char ether_shost[6]; 
            u_short ether_type;  
        };

        // IP header
        struct sniff_ip {
            u_char ip_vhl;     
            u_char ip_tos;   
            u_short ip_len; 
            u_short ip_id;    
            u_short ip_off;  
            u_char ip_ttl;    
            u_char ip_p; 
            u_short ip_sum;     
            struct in_addr ip_src, ip_dst;
        };

        // TCP header
        struct sniff_tcp {
            u_short th_sport;   
            u_short th_dport;    
            u_int32_t th_seq;  
            u_int32_t th_ack;    
            u_char th_offx2;  
            u_char th_flags;
            u_short th_win;   
            u_short th_sum;     
            u_short th_urp;   
        };

        // UDP header
        struct sniff_udp {
            u_short uh_sport; 
            u_short uh_dport;  
            u_short uh_ulen;     
            u_short uh_sum;      
        };

        struct EthernetHeader {
            std::string sourceMac;
            std::string destMac;
            uint16_t etherType;
        };

        struct IPHeader {
            uint8_t version;
            uint8_t headerLength;
            std::string sourceIP;
            std::string destIP;
            uint8_t protocol;
        };

        struct TCPHeader {
            uint16_t sourcePort;
            uint16_t destPort;
            uint32_t sequenceNumber;
            uint32_t acknowledgmentNumber;
            uint8_t dataOffset;
            uint8_t flags;
            uint16_t windowSize;
        };

        struct UDPHeader {
            uint16_t sourcePort;
            uint16_t destPort;
            uint16_t length;
            uint16_t checksum;
        };

        struct ParsedPacket {
            EthernetHeader ethernet;
            IPHeader ip;
            union {
                TCPHeader tcp;
                UDPHeader udp;
            } transport;
            bool isTCP;
            std::vector<uint8_t> payload;
        };

        ProtocolParser() = default;
        ~ProtocolParser() = default;

        ParsedPacket parsePacket(const uint8_t* rawData, size_t dataLength);

    private:
        static const size_t SIZE_ETHERNET = 14; 

        EthernetHeader parseEthernet(const struct sniff_ethernet* header);
        IPHeader parseIP(const struct sniff_ip* header);
        TCPHeader parseTCP(const struct sniff_tcp* header);
        UDPHeader parseUDP(const struct sniff_udp* header);

        std::string macToString(const uint8_t* mac);
        std::string ipToString(const struct in_addr* addr);

        uint8_t getIPHeaderLength(const struct sniff_ip* ip) { return (ip->ip_vhl & 0x0f) * 4; }

        uint8_t getTCPHeaderLength(const struct sniff_tcp* tcp) { return ((tcp->th_offx2 & 0xf0) >> 4) * 4; }

};
   
#endif