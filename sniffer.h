#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>

void bailout(int signo);
void parsePacket(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void captureLoop(pcap_t* pd, int packets, pcap_handler func);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
pcap_t* openPcapSocet(char *device, const char *bpfstr);
#endif /* SNIFFER_H */
