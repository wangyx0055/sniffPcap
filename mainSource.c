#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

pcap_t *pd;
int linkhdrlen;

void bailout(int signo);
void parsePacket(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void captureLoop(pcap_t* pd, int packets, pcap_handler func);
pcap_t* openPcapSocet(char *device, const char *bpfstr);



int main(int argc, char **argv)
{
    char interface[256] = "";
    char bpfstr[256] = "";
    int packets = 0;
    int c, i;

    // get cmd line options
    while ((c = getopt (argc, argv, "hi:n:")) != -1)
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
    }

    // get the packet capture filter expr
    for (i = optind; i < argc; i++)
    {
        strcat(bpfstr, argv[i]);
        strcat(bpfstr, " ");
    }

    // open libpcac, sets signal and start capture
    if ((pd = openPcapSocet(interface, bpfstr)))
    {
        signal(SIGINT, bailout);
        signal(SIGTERM, bailout);
        signal(SIGQUIT, bailout);
        captureLoop(pd, packets, (pcap_handler)parsePacket);
    }
    return 0;
}

pcap_t* openPcapSocet(char *device, const char *bpfstr)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *pd;
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
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;

    // skip datalink layer header and get the IP header fields
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
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
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
               dstip, ntohs(udphdr->dest));
        printf("%s\n", iphdrInfo);
        break;

    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        memcpy(&id, (u_char*)icmphdr+4, 2);
        memcpy(&seq, (u_char*)icmphdr+6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
               ntohs(id), ntohs(seq));
        break;
    }
    printf("******************************\n\n");
}

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
