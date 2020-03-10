#ifndef PACKET_STRUCTURE_H
#define PACKET_STRUCTURE_H
#include <pcap.h>

#pragma pack(push, 1)
struct ethheader{
    uint8_t Dhost[6];
    uint8_t Shost[6];
    uint16_t Nlayer;
};
struct ipheader{
    uint8_t hlen:4, ver:4;
    uint8_t DSF;
    uint16_t Totlen;
    uint16_t ID;
    uint16_t Flag;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t checksum;
    uint8_t Sip[4];
    uint8_t Dip[4];
};
struct tcpheader{
    uint16_t Sport;
    uint16_t Dport;
    uint32_t Seqnum;
    uint32_t Acknum;
    uint16_t hlenFlag;
    uint16_t Size;
    uint16_t checksum;
    uint16_t Urgpointer;
};
#pragma pack(pop)



#endif // PACKET_STRUCTURE_H
