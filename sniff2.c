/*
    gcc -o sniffer main.c -lpcap
*/
#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <ctype.h>

struct my_ip {
    u_int8_t    ip_vhl;
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;
    u_int16_t   ip_len;
    u_int16_t   ip_id;
    u_int16_t   ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x01fff
    u_int8_t    ip_ttl;
    u_int8_t    ip_p;
    u_int16_t   ip_sum;
    struct  in_addr ip_src, ip_dst;
};
void handle_tcp(u_char *args, const struct pcap_pkthdr* pkthdr,
        const u_char* packet, u_int16_t len);

#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (16 / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5
#define HEXDUMP_HEXSTUFF_PER_LINE 40
void ascii_print_with_offset(register const u_char *cp,
            register u_int length, register u_int oset)
{
    register u_int i=0;
    register int s1, s2;
    register int nshorts;
    char hexstuff[HEXDUMP_SHORTS_PER_LINE *
            HEXDUMP_HEXSTUFF_PER_SHORT + 1], *hsp;
    char asciistuff[HEXDUMP_BYTES_PER_LINE+1], *asp;

    nshorts=length/sizeof(u_short);
    hsp=hexstuff; asp=asciistuff;
    while(--nshorts>=0) {
        s1=*cp++;
        s2=*cp++;
        (void)snprintf(hsp, sizeof(hexstuff)-(hsp-hexstuff)," %02x%02x", s1, s2);
        hsp+=HEXDUMP_HEXSTUFF_PER_SHORT;
        *(asp++)=(isgraph(s1) ? s1 : '.');
        *(asp++)=(isgraph(s2) ? s2 : '.');
        if(++i >= HEXDUMP_SHORTS_PER_LINE) {
            *hsp=*asp='\0';
            printf("\n0x%04x\t%-*s\t%s", oset,
                 HEXDUMP_HEXSTUFF_PER_LINE,
                hexstuff, asciistuff);
            i=0; hsp=hexstuff; asp=asciistuff;
            oset+=HEXDUMP_BYTES_PER_LINE;
        }
    }
    if(length & 1) {
        s1=*cp++;
        (void)snprintf(hsp, sizeof(hexstuff)-(hsp-hexstuff)," %02x", s1);
        hsp+=3;
        *(asp++)=(isgraph(s1) ? s1 : '.');
        ++i;
    }
    if(i>0) {
        *hsp=*asp='\0';
        (void)printf("\n0x%04x\t%-*s\t%s", oset, HEXDUMP_HEXSTUFF_PER_LINE,
                hexstuff, asciistuff);
    }
}

u_short handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct ether_header *eth;

    eth=(struct ether_header *) packet;
    printf("ETH\tsource: %s", ether_ntoa(eth->ether_shost));
    printf(" dest: %s\n", ether_ntoa(eth->ether_dhost));

    return ntohs(eth->ether_type);
}

void handle_ip(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct my_ip* ip;

    ip=(struct my_ip *)(packet+sizeof(struct ether_header));
    printf("IP\tsource: %s ", inet_ntoa(ip->ip_src));
    printf("dest: %s\n", inet_ntoa(ip->ip_dst));
    printf("\ttos: %d len: %d id: %d ttl: %d\n", ip->ip_tos, ip->ip_len,
        ip->ip_id, ip->ip_ttl);
    if(ip->ip_p==IPPROTO_TCP){ handle_tcp(args, pkthdr, packet, ip->ip_len);
    } else if(ip->ip_p==IPPROTO_UDP) { printf("(UDP)\n");
    } else if(ip->ip_p==IPPROTO_ICMP) { printf("(ICMP)\n");
    } else { printf("UNKNOWN\n"); }
}

void handle_tcp(u_char *args, const struct pcap_pkthdr* pkthdr,
        const u_char* packet, u_int16_t len)
{
    struct tcphdr* tcp;
    u_char *data;
    int iplen=sizeof(struct ether_header)+sizeof(struct my_ip);
    int tcplen=iplen+sizeof(struct tcphdr);

    tcp=(struct tcphdr *)(packet+iplen);
    printf("TCP\tsport: %d", ntohs(tcp->th_sport));
    printf(" dport: %d\n", ntohs(tcp->th_dport));
    //data=(u_char *)(packet+tcplen);
    //len=len-(sizeof(struct my_ip)+sizeof(struct tcphdr));
    //ascii_print_with_offset(data, len, 0);
    printf("\n\n");
}

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    u_int16_t etype=handle_ethernet(args, pkthdr, packet);
    if(etype==ETHERTYPE_IP) { handle_ip(args, pkthdr, packet);
    } else if(etype==ETHERTYPE_ARP) { printf("(ARP)\n");
    } else if(etype==ETHERTYPE_REVARP) { printf("(RARP)\n");
    } else { printf("(UNKNOWN)\n"); }
}

int main(int argc, char *argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct bpf_program fp;
    struct in_addr addr;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    if(argc==2) {
        if((dev=pcap_lookupdev(errbuf))==NULL) {
            printf("%s\n", errbuf); exit(1); }
        pcap_lookupnet(dev, &netp, &maskp, errbuf);
        if((descr=pcap_open_live(dev, BUFSIZ, 1, 0, errbuf))==NULL) {
            printf("pcap_open_live(): %s\n", errbuf); exit(1); }
        if(pcap_compile(descr, &fp, argv[2], 0, netp)==-1) {
            printf("Error pcap_compile()\n"); exit(1); }
        if(pcap_setfilter(descr, &fp)==-1) {
            printf("Error pcap_setfilter\n"); exit(1); }
        printf("DEV: %s\n", dev);
        addr.s_addr=netp;
        printf("NET: %s\n", inet_ntoa(addr));
        addr.s_addr=maskp;
        printf("MASK: %s\n", inet_ntoa(addr));
        pcap_loop(descr, -1, callback, NULL);
        pcap_close(descr);
    } else {
        printf("Usage: %s \"filter\"\n", argv[0]);
    }

    return 0;
}
