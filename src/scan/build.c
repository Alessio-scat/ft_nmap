#include "ft_nmap.h"

/*
 * tcph->ack_seq: Acknowledgment number, set to 0 for scans.
 * tcph->doff: Data offset, specifies the size of the TCP header (minimum 5).
 * tcph->syn: SYN flag, set for SYN scans to initiate a connection.
 * tcph->fin: FIN flag, set for FIN or XMAS scans to indicate connection termination.
 * tcph->rst: RST flag, always set to 0 for scan packets.
 * tcph->psh: PSH flag, set for XMAS scans to push data immediately.
 * tcph->urg: URG flag, set for XMAS scans to indicate urgent data.
 * tcph->ack: ACK flag, set for ACK scans to acknowledge a connection.
 * tcph->window: Window size for the TCP packet, set to a fixed value (5840).
 * tcph->check: Checksum field, initially 0 and calculated later.
 * tcph->urg_ptr: Urgent pointer, set to 0 for scans.
 * htonl: Converts a 32-bit integer from host byte order to network byte order (big-endian).
 * Commonly used for IP addresses and other 32-bit values in network communication.
 * htons: Converts a 16-bit integer from host byte order to network byte order (big-endian).
 * Commonly used for port numbers and other 16-bit values in network communication.
 */



int create_raw_socket() {
    int optval = 1;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Error creating raw socket");
        exit(1);
    }
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }
    return sockfd;
}

int create_udp_socket() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Error creating UDP socket");
        exit(1);
    }
    return sockfd;
}

// Function to build the IP header
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(options->local_ip);
    iph->daddr = dest->sin_addr.s_addr;

    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
}

void build_tcp_header(struct tcphdr *tcph, int target_port, ScanOptions *options) {
    tcph->source = htons(20000 + options->scan_type);
    tcph->dest = htons(target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // TCP Header Length
    if (options->scan_type == SYN){
        tcph->syn = 1;
    }
    else
        tcph->syn = 0;
    if (options->scan_type == FIN || options->scan_type == XMAS) {
        tcph->fin = 1; 
    }
    else
        tcph->fin = 0; 
    tcph->rst = 0; 
    if (options->scan_type == XMAS){
        tcph->psh = 1;   
        tcph->urg = 1;   
    }
    else{
        tcph->psh = 0;   
        tcph->urg = 0; 
    }
    if (options->scan_type == ACK) {
        tcph->ack = 1; 
    }
    else
        tcph->ack = 0; 
    tcph->window = htons(5840);  // TCP Window Size
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void build_ip_header_udp(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(options->local_ip);
    iph->daddr = dest->sin_addr.s_addr;

    // Calcul du checksum pour l'en-tête IP
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
}

void build_udp_header_udp(struct udphdr *udph, int target_port) {
    udph->source = htons(rand() % 65535 + 1024);
    udph->dest = htons(target_port);
    udph->len = htons(sizeof(struct udphdr));
    udph->check = 0;
}

