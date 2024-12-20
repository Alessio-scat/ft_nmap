#include "ft_nmap.h"

/*
 * ntohs: Converts a 16-bit integer from network byte order (big-endian) to host byte order.
 * Commonly used to interpret port numbers received in network packets.
 */


void os_detection(const struct iphdr *iph, ScanOptions *options){
    if(options->OS == 1)
    {
        if (options->ttl == 0) {
            options->ttl = iph->ttl;
        }
    }
}

void findCurrent(ScanOptions *options){
    for(int i = 0; i < options->scan_count; i++){
        if(options->tabscan[i] == options->scan_type){
            options->currentScan = i;
            return;
        }
    }
}

void findScanType(struct tcphdr *tcph, ScanOptions *options){
    if (tcph->dest == htons(20000 + SYN)) {
        options->scan_type = SYN;
        findCurrent(options);
    } else if (tcph->dest == htons(20000 + ACK)) {
        options->scan_type  = ACK;
        findCurrent(options);
    } else if (tcph->dest == htons(20000 + FIN)) {
        options->scan_type = FIN;
        findCurrent(options);
    } else if (tcph->dest == htons(20000 + SCAN_NULL)) {
        options->scan_type = SCAN_NULL;
        findCurrent(options);
    } else if (tcph->dest == htons(20000 + XMAS)) {
        options->scan_type = XMAS;
        findCurrent(options);
    }
}

void handle_icmp_packet(const struct iphdr *iph, const u_char *packet, ScanOptions *options) {
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + iph->ihl * 4);
    struct iphdr *inner_iph = (struct iphdr *)(packet + 14 + iph->ihl * 4 + sizeof(struct icmphdr));
    int inner_ip_header_length = inner_iph->ihl * 4;

    if (inner_iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((char *)inner_iph + inner_ip_header_length);
        findScanType(tcph, options);
 
        if (icmp_header->type == 3) {
            int code = icmp_header->code;
            if (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13) {
                int port = ntohs(((struct tcphdr *)(packet + 14 + iph->ihl * 4 + sizeof(struct icmphdr)))->dest);
                
                if (port > 0 && port <= MAX_PORT)
                    strcpy(options->status[options->currentScan][port - 1], "FILTERED");
            }
        }
    }
    else{
        struct udphdr *udph = (struct udphdr *)((u_char *)inner_iph + inner_ip_header_length);
        int port = ntohs(udph->dest);
        options->scan_type = UDP;
        findCurrent(options);
        if (icmp_header->type == 3) {
            switch (icmp_header->code) {
                case 3:  // ICMP port unreachable
                    if (port > 0 && port <= MAX_PORT){
                        strcpy(options->status[options->currentScan][port - 1], "CLOSED");
                    }
                    break;

                case 1: case 2: case 9: case 10: case 13:
                    if (port > 0 && port <= MAX_PORT)
                        strcpy(options->status[options->currentScan][port - 1], "FILTERED");
                    break;

                default:
                    printf("Other ICMP response type not supported for port : %d\n", port);
                    break;
            }
        }
    }
}

// Function to process TCP packets
void handle_tcp_packet(const struct iphdr *iph, const u_char *packet, ScanOptions *options) {
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4);
    int port = ntohs(tcph->source);

    if (port <= 0 || port > MAX_PORT)
        return;

    findScanType(tcph, options);
    // Check if the port already has a final status (eg. CLOSED)
    if (strcmp(options->status[options->currentScan][port - 1], "CLOSED") == 0 ||
        strcmp(options->status[options->currentScan][port - 1], "OPEN") == 0 ||
        strcmp(options->status[options->currentScan][port - 1], "UNFILTERED") == 0) {
        return; 
    }
    if (options->scan_type == SYN) {  // Scan SYN
        if (tcph->syn == 1 && tcph->ack == 1) {
            os_detection(iph, options);
            strcpy(options->status[options->currentScan][port - 1], "OPEN");
        } else if (tcph->rst == 1) {
            strcpy(options->status[options->currentScan][port - 1], "CLOSED");
        }
    } else if (options->scan_type == SCAN_NULL || options->scan_type == FIN || options->scan_type == XMAS) {  // Scans FIN, NULL, XMAS
        if (tcph->rst == 1) {
            os_detection(iph, options);
            strcpy(options->status[options->currentScan][port - 1], "CLOSED");
        } else {
            strcpy(options->status[options->currentScan][port - 1], "OPEN|FILTERED");
        }
    } else if (options->scan_type == ACK) {  // Scan ACK
        if (tcph->rst == 1) {
            os_detection(iph, options);
            strcpy(options->status[options->currentScan][port - 1], "UNFILTERED");
        } else {
            strcpy(options->status[options->currentScan][port - 1], "FILTERED");
        }
    }
}

// Manage packets
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;
    ScanOptions *options = (ScanOptions *)user_data;
    struct iphdr *iph = (struct iphdr *)(packet + 14);
    struct in_addr source_addr;
    source_addr.s_addr = iph->saddr;

    // Ignore chunks other IP
    if (strcmp(inet_ntoa(source_addr), options->ip_address) != 0) {
        return;
    }
    
    if (iph->protocol == IPPROTO_ICMP)
        handle_icmp_packet(iph, packet, options);
    else if (iph->protocol == IPPROTO_TCP)
        handle_tcp_packet(iph, packet, options);
    else if (iph->protocol == IPPROTO_UDP) {
        // skip Ethernet and Ip header
        struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ihl * 4);
        int port = ntohs(udph->source); 
        options->scan_type = UDP;
        findCurrent(options);
        if (port > 0 && port <= MAX_PORT){
            os_detection(iph, options);
            strcpy(options->status[options->currentScan][port - 1], "OPEN");
        }
    }
    alarm(5);
}