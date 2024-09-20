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


typedef struct {
    char *ip_address;
    char *ports;
    char *file;
    int speedup;
    char *scan_type;
} ScanOptions;

/*
    parsing.c
*/
void parse_arguments(int ac, char **av, ScanOptions *options);


#endif