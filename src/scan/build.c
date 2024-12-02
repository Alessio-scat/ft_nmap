#include "ft_nmap.h"

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

// Fonction pour construire l'en-tête IP en utilisant ScanOptions
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321); // ID unique
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Checksum sera calculé après
    iph->saddr = inet_addr(options->local_ip); // Utilisation de l'IP locale stockée dans ScanOptions
    iph->daddr = dest->sin_addr.s_addr;

    // Calcul du checksum pour l'en-tête IP
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
}

// Fonction pour construire l'en-tête TCP correctement (seulement le SYN doit être activé)
void build_tcp_header(struct tcphdr *tcph, int target_port, ScanOptions *options) {
    tcph->source = htons(20000 + options->scan_type);  // Port source aléatoire
    tcph->dest = htons(target_port);  // Port cible
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // Longueur de l'en-tête TCP
    if (options->scan_type == SYN){
        tcph->syn = 1;
    }
    else
        tcph->syn = 0;
    if (options->scan_type == FIN || options->scan_type == XMAS) {
        tcph->fin = 1; 
    }
    else
        tcph->fin = 0;   // Flag FIN désactivé
    tcph->rst = 0;   // Flag RST désactivé
    if (options->scan_type == XMAS){
        tcph->psh = 1;   
        tcph->urg = 1;   
    }
    else{
        tcph->psh = 0;   // Flag PSH désactivé
        tcph->urg = 0;   // Flag URG désactivé
    }
    if (options->scan_type == ACK) {
        tcph->ack = 1; 
    }
    else
        tcph->ack = 0;   // Flag ACK désactivé
    tcph->window = htons(5840);  // Taille de la fenêtre TCP
    tcph->check = 0;  // Le checksum sera calculé plus tard
    tcph->urg_ptr = 0;  // Pointeur urgent désactivé
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

