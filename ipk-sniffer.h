#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include <pcap/sll.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/ipv6.h>
#include <time.h>
#include <ctype.h>
struct sockaddr_in source, dest;
struct sockaddr_in6 sourcev6, destv6;
int counter = 0;
char *pkt_type;

void processing(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void process_data(const u_char *data, int size, char *type);
void process_header(const u_char *buffer, char *type);
void process_headerv6(const u_char *buffer, char *type);