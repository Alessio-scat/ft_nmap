#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <pcap.h>
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

#define MAX_PORT 1024

typedef struct {
    char *ip_address;
    char *ports;
    int speedup;
    char *scan_type;
    int portsTab[MAX_PORT];
    int portsTabSize;   
    //file
    char *file;
    char **ip_list;
    int ip_count;
    
} ScanOptions;

typedef struct {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
} psh;

/*
    parsing.c
*/
void parse_arguments(int ac, char **av, ScanOptions *options);

//scan SYN
int syn_scan(char *target_ip, int target_port);

//utils.c
unsigned short checksum(void *b, int len);
char *get_local_ip();

#endif