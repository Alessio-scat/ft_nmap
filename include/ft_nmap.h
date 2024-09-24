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

#define MAX_PORT 1024

typedef struct {
    char *ip_address;
    char *ports;
    int speedup;
    char *scan_type;
    int portsTab[1024];
    int portsTabSize;   
    //file
    char *file;
    char **ip_list;
    int ip_count;
    
} ScanOptions;

typedef struct {
    char *ip;
    int *ports;
    int start_index;
    int end_index;
    char *scan_type;
} ScanTask;

/*
    parsing.c
*/
void parse_arguments(int ac, char **av, ScanOptions *options);


#endif