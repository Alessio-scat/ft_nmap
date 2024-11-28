#include "ft_nmap.h"

void os_detection(const struct iphdr *iph, ScanOptions *options){
    if(options->OS == 1)
    {
        if (options->ttl == 0) {
            options->ttl = iph->ttl;
        }
    }
}

void handle_icmp_packet(const struct iphdr *iph, const u_char *packet, ScanOptions *options) {
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + iph->ihl * 4);
    // printf("ICMP\n");

    if (options->scan_type == SCAN_NULL || options->scan_type == FIN || options->scan_type == XMAS) {
        // Vérifier le type et le code ICMP pour déterminer si le port est filtré
        if (icmp_header->type == 3) { // Type 3 : Destination Unreachable
            int code = icmp_header->code;
            if (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13) {
                int port = ntohs(((struct tcphdr *)(packet + 14 + iph->ihl * 4 + sizeof(struct icmphdr)))->dest);
                
                // Vérifier que le port est dans les limites
                if (port > 0 && port <= MAX_PORT) {
                    // Marquer le port comme filtré
                    strcpy(options->status[options->currentScan][port - 1], "FILTERED");
                }
            }
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
void print_tcphdr(struct tcphdr *tcph) {
    printf("===== TCP Header =====\n");
    printf("Source Port: %u\n", ntohs(tcph->source));
    printf("Destination Port: %u\n", ntohs(tcph->dest));
    printf("Sequence Number: %u\n", ntohl(tcph->seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcph->ack_seq));
    printf("Data Offset: %u (Header Length: %u bytes)\n", tcph->doff, tcph->doff * 4);
    printf("Flags:\n");
    printf("  SYN: %d\n", tcph->syn);
    printf("  ACK: %d\n", tcph->ack);
    printf("  FIN: %d\n", tcph->fin);
    printf("  RST: %d\n", tcph->rst);
    printf("  PSH: %d\n", tcph->psh);
    printf("  URG: %d\n", tcph->urg);
    printf("Window Size: %u\n", ntohs(tcph->window));
    printf("Checksum: 0x%x\n", ntohs(tcph->check));
    printf("Urgent Pointer: %u\n", ntohs(tcph->urg_ptr));
    printf("======================\n");
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

// Fonction pour traiter les paquets TCP
void handle_tcp_packet(const struct iphdr *iph, const u_char *packet, ScanOptions *options) {
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4);
    int port = ntohs(tcph->source);
    if (port <= 0 || port > MAX_PORT) {
        return; // Ignorer les ports hors limites
    }
    // print_tcphdr(tcph);
    findScanType(tcph, options);
    // printf("passe %d %d\n", options->scan_type, port);
// Ajoutez d'autres vérifications pour les autres techniques.
    // Vérifier si le port a déjà un statut final (ex. CLOSED)
    if (strcmp(options->status[options->currentScan][port - 1], "CLOSED") == 0 ||
        strcmp(options->status[options->currentScan][port - 1], "OPEN") == 0 ||
        strcmp(options->status[options->currentScan][port - 1], "UNFILTERED") == 0) {
        return; // Ne pas modifier un port qui a déjà un statut final
    }
    // Traitement en fonction du type de scan
    if (options->scan_type == SYN) {  // Scan SYN
        if (tcph->syn == 1 && tcph->ack == 1) {
            os_detection(iph, options);
        printf("opennnnnnnnnnnnn\n");
            strcpy(options->status[options->currentScan][port - 1], "OPEN");
        } else if (tcph->rst == 1) {
            strcpy(options->status[options->currentScan][port - 1], "CLOSED");
        }
    } else if (options->scan_type == SCAN_NULL || options->scan_type == FIN || options->scan_type == XMAS) {  // Scans FIN, NULL, XMAS
        if (tcph->rst == 1) {
            strcpy(options->status[options->currentScan][port - 1], "CLOSED");
        } else {
            os_detection(iph, options);
            strcpy(options->status[options->currentScan][port - 1], "OPEN|FILTERED");
        }
    } else if (options->scan_type == ACK) {  // Scan ACK
        if (tcph->rst == 1) {
            // printf("unfiltred %d\n", port);
            strcpy(options->status[options->currentScan][port - 1], "UNFILTERED");
        } else {
            // printf("filtred %d\n", port);
            os_detection(iph, options);
            strcpy(options->status[options->currentScan][port - 1], "FILTERED");
        }
    }
}

// Fonction principale de gestion des paquets
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;
    // Récupération des données utilisateur (ScanOptions)
    ScanOptions *options = (ScanOptions *)user_data;

    // Sauter l'en-tête Ethernet (14 octets)
    struct iphdr *iph = (struct iphdr *)(packet + 14);
    
    // Vérifier si le paquet provient de l'IP cible
    struct in_addr source_addr;
    source_addr.s_addr = iph->saddr;
    if (strcmp(inet_ntoa(source_addr), options->ip_address) != 0) {
        // Ignorer les paquets provenant d'autres IPs
        return;
    }
    // Gérer le TTL de la cible si nécessaire
    

    // Appeler les fonctions appropriées en fonction du protocole
    if (iph->protocol == IPPROTO_ICMP) {
        handle_icmp_packet(iph, packet, options);
    } else if (iph->protocol == IPPROTO_TCP) {
        handle_tcp_packet(iph, packet, options);
    }

    // Mettre une alarme ou un délai si nécessaire
    alarm(5);
}