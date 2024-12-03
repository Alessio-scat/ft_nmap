#include "ft_nmap.h"



void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest) {
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Declares and initializes the pseudo-header for checksum calculation
    psh pshdr;
    pshdr.source_address = iph->saddr; 
    pshdr.dest_address = iph->daddr; 
    pshdr.placeholder = 0; // Fill field
    pshdr.protocol = IPPROTO_TCP; // Protocol TCP
    pshdr.tcp_length = htons(sizeof(struct tcphdr)); // TCP Header Length

    // Total size for checksum calculation (pseudo-header + TCP header)
    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    if (pseudogram == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for pseudogram\n");
        exit(EXIT_FAILURE);
    }

    // Copy pseudo-header and TCP header into buffer for computation
    memcpy(pseudogram, (char *)&pshdr, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));

    // Calculate TCP checksum using pseudo-header and TCP header
    tcph->check = checksum((unsigned short *)pseudogram, psize);

    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("Échec de l'envoi du paquet");
    }
    free(pseudogram);
}


void send_all_packets(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];

        dest->sin_port = htons(target_port);

        if (options->scan_type == UDP) {
            memset(packet, 0, 4096);
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

            build_udp_header_udp(udph, target_port);

            if (sendto(sock, packet, htons(iph->tot_len), 0,
                       (struct sockaddr *)dest, sizeof(*dest)) < 0) {
                perror("Failed to send UDP packet");
            }
        } else {
            build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
            send_packet(sock, packet, iph, dest);
        }
        usleep(1000);
    }
}
