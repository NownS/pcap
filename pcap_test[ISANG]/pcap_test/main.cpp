#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <packet_structure.h>

uint16_t uint16_LtoB(uint16_t value);


struct application{
    uint8_t value[16];
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    ethheader * ethernet = (ethheader*) packet;
    printf("Eth header\n");
    printf("Source Mac Addr [");
    for(int i=0;i<6;i++)
        printf("%02X:", ethernet->Shost[i]);
    printf("\b]\t");
    printf("Destination Mac Addr [");
    for(int i=0;i<6;i++)
        printf("%02X:", ethernet->Dhost[i]);
    printf("\b]\n\n");
    //-----------------------------------------eth header print
    ipheader* ip;
    if(ntohs(ethernet->Nlayer)==0x0800)
    {
        ip = (ipheader*) packet+14; // add offset
    }
    else
    {
        printf("%u bytes captured\n", header->caplen);
        printf("--------------------------------------------------------------------------------------------------\n");
        continue;
    }
    printf("ip header\n");
    printf("Source ip : %d.%d.%d.%d\t", ip->Sip[0],ip->Sip[1],ip->Sip[2],ip->Sip[3]);
    printf("Destination ip : %d.%d.%d.%d\n\n", ip->Dip[0],ip->Dip[1],ip->Dip[2],ip->Dip[3]);
    //------------------------------------------ip header print
    tpheader *tcp;
    if(ip->Protocol==6) tcp = (tcpheader*)packet+ip->hlen*4;
    else
    {
        printf("%u bytes captured\n", header->caplen);
        printf("--------------------------------------------------------------------------------------------------\n");
        continue;
    }
    printf("tcp header \n");
    printf("Source port : ");
    printf("%d\t", uint16_LtoB(tcp->Sport));
    printf("Destination port : %d\n\n",uint16_LtoB(tcp->Dport));
    //------------------------------------------tcp header print
    int paylen=(int)uint16_LtoB(ip->Totlen)-((int)ip->hlen)*4-(int)((tcp->hlenFlag>>4)&15)*4;
    if(!paylen)
    {
        printf("%u bytes captured\n", header->caplen);
        printf("--------------------------------------------------------------------------------------------------\n");
        continue;
    }
    else
    {
        packet=packet+sizeof(tcpheader);
    }
    application * app = (application*) packet;
    printf("application Layer value\n");
    for(int i=0;i<16;i++) printf("%02X ",app->value[i]);
    printf("\n\n");
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("--------------------------------------------------------------------------------------------------\n");
  }

  pcap_close(handle);
  return 0;
}

uint16_t uint16_LtoB(uint16_t value)
{
    uint16_t temp;
    temp=value;
    value=value>>8;
    temp=temp<<8;
    return (uint16_t)(temp | value);
}
