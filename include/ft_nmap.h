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
    //file
    char *file;
    char **ip_list;
    int ip_count;
    char *local_ip;
    char *local_interface;
    char ***status;
    int scan_count;
    int tabscan[MAX_SCANS];
    int currentScan;
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
    int target_port;      // Port cible à analyser
    int port_status;      // Statut du port (ouvert, fermé, filtré)
} pcap_data_t;



/*
    parsing.c
*/
void parse_arguments(int ac, char **av, ScanOptions *options);

//scan SYN
void tcp_scan_all_ports(ScanOptions *options);

//utils.c
unsigned short checksum(void *b, int len);
char *get_local_ip();
char *get_local_interface();
void print_scan_result(int port, const char *service, const char *state);
void print_help();

void initialize_status(ScanOptions *options, int num_techniques, int num_ports);
void print_ports_excluding_state(ScanOptions *options, char *excluded_state);
const char* get_scan_name(int scan_code);

#endif