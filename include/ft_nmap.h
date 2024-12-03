#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <regex.h>
#include <ctype.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

extern bool stop_pcap;


#define MAX_PORT 1024
#define PORT_OPEN 1
#define PORT_CLOSED 0
#define PORT_FILTERED -1

#define SYN 1
#define SCAN_NULL 2
#define FIN 3
#define XMAS 4
#define ACK 5
#define UDP 6

#define MAX_SCANS 6

typedef struct {
    char *ip_address;
    char *ip_host;
    char *ports;
    int speedup;
    int scan_type;
    int portsTab[MAX_PORT];
    int flag_ports;
    int portsTabSize;  
    char *file;
    char **ip_list;
    int ip_count;
    char *local_ip;
    char *local_interface;
    char ***status;
    int scan_count;
    int tabscan[MAX_SCANS];
    int currentScan;
    int ttl;
    int OS;
} ScanOptions;

typedef struct {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
} psh;

typedef struct {
    pcap_t *pcap_handle;  // Handle de capture pcap
    int target_port;      // Target port to scan
    int port_status;      // Port status (open, closed, filtered)
} pcap_data_t;

typedef struct {
    int thread_id;
    ScanOptions *options;
    int start_scan;  // Starting scan index (type)
    int end_scan;    // End scan index (type)
    int start_port;  // Port of departure
    int end_port;    // End port
    struct sockaddr_in dest;
} ScanThreadData;

extern pcap_t *global_handle;
extern ScanOptions *global_options;


/*
    parsing.c
*/
void parse_arguments(int ac, char **av, ScanOptions *options);
void handle_ip_option_in_file(int *ip_index, ScanOptions *options);


//scan
void tcp_scan_all_ports(ScanOptions *options);
void udp_scan_all_ports(ScanOptions *options);
void *tcp_scan_all_ports_thread(void *arg);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest);
void send_all_packets(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options);
pcap_t *init_pcap(const char *interface);
void wait_for_responses(pcap_t *handle, ScanOptions *options);

//utils.c
unsigned short checksum(void *b, int len);
char *get_local_ip(int use_loopback, ScanOptions *options);
char *get_local_interface(int use_loopback, ScanOptions *options);
void print_help();
void reset_status(ScanOptions *options, int scan_count, int max_ports);

void initialize_status(ScanOptions *options, int num_techniques, int num_ports);
void print_ports_excluding_state(ScanOptions *options, char *excluded_state);
const char* get_scan_name(int scan_code);

//build
void build_tcp_header(struct tcphdr *tcph, int target_port, ScanOptions *options);
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options);
int create_raw_socket();

//thread
void run_scans_by_techniques(ScanOptions *options);
void build_tcp_header_thread(struct tcphdr *tcph, int target_port, int scan_type);
void *threaded_scan(void *arg);

int create_udp_socket();
void build_udp_header_udp(struct udphdr *udph, int target_port);
void build_ip_header_udp(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options);

//signal
void signal_handler(int signum);

//free
void free_nmap(ScanOptions *options);

void cleanup_options(ScanOptions *options);

#endif