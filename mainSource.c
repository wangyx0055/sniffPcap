#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>


#include <unistd.h> // for parsing input (getopt)
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h> //reserved
//#include <netinet/in.h>  //reserved
#include <netinet/ip.h> // ip struct
//#include <netinet/ip_icmp.h> //icmp struct
//#include <netinet/tcp.h> // tcp struct
#include <netinet/udp.h> // udp struct

#include <arpa/inet.h>

//#include <pcap.h> // moved to header
#include "sniffer.h"

#define SIZE_UDP           8  // length of UDP header
#define SIZE_ETHERNET      14 // size of etherned headers, always has 14 bytes
#define ETHER_ADDR_LEN     6  // size of ethernet addresses


// some macroses
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


pcap_t *pd;

int linkhdrlen;

// udp struct header
struct sniff_udp {
         u_short uh_sport;  // source port
         u_short uh_dport;  // destination port
         u_short uh_ulen;   // udp length
         u_short uh_sum;    // udp checksum
};

// ip struct header
struct sniff_ip {
        u_char  ip_vhl;                 // version << 4 | header length >> 2
        u_char  ip_tos;                 // type of service
        u_short ip_len;                 // total length
        u_short ip_id;                  // identification
        u_short ip_off;                 // fragment offset field
        #define IP_RF 0x8000            // reserved fragment flag
        #define IP_DF 0x4000            // dont fragment flag
        #define IP_MF 0x2000            // more fragments flag
        #define IP_OFFMASK 0x1fff       // mask for fragmenting bits
        u_char  ip_ttl;                 // time to live
        u_char  ip_p;                   // protocol
        u_short ip_sum;                 // checksum
        struct  in_addr ip_src,ip_dst;  // source and dest address
};

// ethernet struct header
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    // destination host address
        u_char  ether_shost[ETHER_ADDR_LEN];    // source host address
        u_short ether_type;                     // IP? ARP? RARP? etc
};


int main(int argc, char **argv)
{
    char interface[256] = "";
    char bpfstr[256] = "";
    int packets = 0;
//    int c, i;

    // get cmd line options
   /* while ((c = getopt (argc, argv, "hi:n:")) != -1)
    {
        switch (c)
        {
        case 'h':
            printf("usage: %s [-h] [-i] [-n] []\n", argv[0]);
            return(0);
            break;
        case 'i':
            strcpy(interface, optarg);
            break;
        case 'n':
            packets = atoi(optarg);
            break;
        }
    }*/

    // get the packet capture filter expr
   /* for (i = optind; i < argc; i++)
    {
        strcat(bpfstr, argv[i]);
        strcat(bpfstr, " ");
    }*/

    // open libpcac, sets signal and start capture
    if ((pd = openPcapSocet(interface, bpfstr)))
    {
        //signal(SIGINT, bailout);
        //signal(SIGTERM, bailout);
        //signal(SIGQUIT, bailout);
        captureLoop(pd, packets, (pcap_handler)parsePacket);
    }
    pcap_close(pd);
    return 0;
}

pcap_t* openPcapSocet(char *device, const char *bpfstr)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    //pcap_t *pd; // del?
    uint32_t srcIp, netmask;
    struct bpf_program bpf;

    // if no network device, get them
    if (!*device && !(device = pcap_lookupdev(errBuf)))
    {
        printf("pcap_lookupdev(): %s\n", errBuf);
        return NULL;
    }

    // open device for live capture
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errBuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errBuf);
    }

    // get network device source Ip and mask
    if (pcap_lookupnet(device, &srcIp, &netmask, errBuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errBuf);
    }

    // convert packet filter expr into packet filter binary
    if(pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    // assign packet filter to pcap socket
    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }
    pcap_freecode(&bpf);
    return pd;
}

void captureLoop(pcap_t* pd, int packets, pcap_handler func)
{
    int linktype;

    // datalink layer type
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }

    // set datalink layer header size
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;

    case DLT_EN10MB:
        linkhdrlen = 14;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;

    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }

    // start capturing packets
    if (pcap_loop(pd, packets, func, 0) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}

void parsePacket(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
    // reserved
    //struct icmphdr* icmphdr; // for icmp
    //struct tcphdr* tcphdr; // for tcp
    //const struct sniff_ethernet *ethernet; // ethernet header

    const struct sniff_ip *ip;              // IP header
    const struct sniff_udp *udp;            // UDP header
    const unsigned char *payload;           // payload of packet

    char iphdrInfo[256], srcip[256], dstip[256];
  //  unsigned short id, seq; // also reserved
    int sizeIp;
    int sizePayload;

    // define ethernet header
   // ethernet = (struct sniff_ethernet*)(packetptr);

    // define/calc ip header offset
    ip = (struct sniff_ip*)(packetptr + SIZE_ETHERNET);

    // skip datalink layer header and get the IP header fields
    strcpy(srcip, inet_ntoa(ip->ip_src));
    strcpy(dstip, inet_ntoa(ip->ip_dst));

    // make string with info
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(ip->ip_id), ip->ip_tos, ip->ip_ttl,
            4*ip->ip_vhl, ntohs(ip->ip_len));
    //printf("%s\n", iphdrInfo);

    sizeIp = IP_HL(ip)*4;
    if (sizeIp < 20) {
        printf("   * Invalid IP header length: %u bytes\n", sizeIp);
        return;
    }
    // reserved for all other proto
    // print source and destination IP addresses
/*    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));*/

    // parse and display the fields based on the type of hearder:
    // tcp, udp or icmp
    switch (ip->ip_p)
    {
    //case IPPROTO_TCP:
    /*    tcphdr = (struct tcphdr*)packetptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
               dstip, ntohs(tcphdr->dest));
        printf("%s\n", iphdrInfo);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);*/
        break;

    case IPPROTO_UDP:
    {
        printf("\n\n******************************\n\n");
        // define/compute udp header offset
        printf("       From: %s\n", inet_ntoa(ip->ip_src));
        printf("         To: %s\n", inet_ntoa(ip->ip_dst));
        udp = (struct sniff_udp*)(packetptr + SIZE_ETHERNET + SIZE_UDP);
        printf("   Src port: %d\n", ntohs(udp->uh_sport));
        printf("   Dst port: %d\n", ntohs(udp->uh_dport));

        // define/compute udp payload (segment) offset
        payload = (u_char *)(packetptr + SIZE_ETHERNET + sizeIp + SIZE_UDP);

        // compute udp payload (segment) size
        sizePayload = ntohs(ip->ip_len) - (sizeIp + SIZE_UDP);
        if (sizePayload > ntohs(udp->uh_ulen))
            sizePayload = ntohs(udp->uh_ulen);


        // print payload data;
        // it might be binary
        // but we treat it as a string.
        if (sizePayload > 0)
        {
            printf("   Payload: (%d bytes):\n", sizePayload);
            printPayload(payload, sizePayload);
        }
        break;
    }
    // reserved
    /*case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        memcpy(&id, (u_char*)icmphdr+4, 2);
        memcpy(&seq, (u_char*)icmphdr+6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
               ntohs(id), ntohs(seq));
        break;*/
    }
}
// ala callback in windows
/*
void bailout(int signo)
{
    struct pcap_stat stats;

    if (pcap_stats(pd, &stats) >= 0)
    {
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
    }
    pcap_close(pd);
    exit(0);
}
*/

// print packet payload data (avoid printing binary data)
void printPayload(const u_char *payload, int len)
{

    int lenRem = len;
    int lineWidth = 16;            // number of bytes per line
    int lineLen;
    int offset = 0;                 // zero-based offset counter
    const u_char *ch = payload;

    if (len <= 0)
        return;

    // data fits on one line
    if (len <= lineWidth) {
        printHexAsciiLine(ch, len, offset);
        return;
    }

    //data spans multiple lines
    while(1)
    {
        // calc current line length
        lineLen = lineWidth % lenRem;
        // print line
        printHexAsciiLine(ch, lineLen, offset);
        // calc total remaining
        lenRem = lenRem - lineLen;
        // shift pointer to remaining bytes to print
        ch = ch + lineLen;
        // add offset
        offset = offset + lineWidth;
        //check if we have line width chars or less
        if (lenRem <= lineWidth)
        {
            // print last line and get out
            printHexAsciiLine(ch, lenRem, offset);
            break;
        }
    }

    return;
}

// print data in rows of 16 bytes:
// offset   hex   ascii
// example:
// 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
void printHexAsciiLine(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    printf("%05d   ", offset); // offset
    // hex
    ch = payload;
    for(i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        // print additional space after 8th byte for beautiful
        if (i == 7)
            printf(" ");
    }
    // print space to handle line less than 8 bytes
    if (len < 8)
        printf(" ");

    // fill hex gap with spaces if not full line
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }
    printf("   ");

    // ascii (if printable)
    ch = payload;
    for(i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");

    return;
}
