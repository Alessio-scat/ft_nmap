#include "ft_nmap.h"

/*
    - Chunk UDP wrong lenght when i analyse with tcpdump
    - Wrong copy when chunk UDP valide in the packer handler
    - Not receive chunk when i not launch command tcpdump
*/

pcap_t *global_handle_udp = NULL;
bool stop_pcap_udp = false;

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



void timeout_handler_udp(int signum) {
    if (signum == SIGALRM) {
        stop_pcap_udp = true;
        if (global_handle_udp) {
            pcap_breakloop(global_handle_udp);  // stop catch pcap
        }
    }
}


int create_udp_socket() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Error creating UDP socket");
        exit(1);
    }
    return sockfd;
}

/*
    https://nmap.org/book/scan-methods-udp-scan.html#scan-methods-tbl-udp-scan-responses
*/

void packet_handler_udp(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("Paquet capturé de longueur : %d\n", pkthdr->len);
    ScanOptions *options = (ScanOptions *)user_data;

    struct iphdr *iph = (struct iphdr *)(packet + 14);  // En-tête IP après l'en-tête Ethernet
    printf("Protocole IP détecté : %d\n", iph->protocol);

    // Cas des paquets ICMP
    if (iph->protocol == IPPROTO_ICMP) {
        printf("Paquet ICMP détecté\n");
        struct icmphdr *icmph = (struct icmphdr *)(packet + 14 + iph->ihl * 4);

        // Extraire les informations du paquet ICMP pour obtenir le port cible
        struct iphdr *inner_iph = (struct iphdr *)(packet + 14 + iph->ihl * 4 + sizeof(struct icmphdr));
        int inner_ip_header_length = inner_iph->ihl * 4;
        struct udphdr *udph = (struct udphdr *)((u_char *)inner_iph + inner_ip_header_length);
        int port = ntohs(udph->dest);

        printf("ICMP type: %d, code: %d\n", icmph->type, icmph->code);
        if (icmph->type == 3) {
            switch (icmph->code) {
                case 3:  // ICMP port unreachable
                    printf("ICMP Port Unreachable reçu pour le port : %d\n", port);
                    if (port > 0 && port <= MAX_PORT) {
                        strcpy(options->status[0][port - 1], "CLOSED");
                    }
                    break;

                case 1: case 2: case 9: case 10: case 13:  // Autres erreurs ICMP "Unreachable"
                    printf("ICMP 'Unreachable' filtré reçu pour le port : %d\n", port);
                    if (port > 0 && port <= MAX_PORT) {
                        strcpy(options->status[0][port - 1], "FILTERED");
                    }
                    break;

                default:
                    printf("Autre type de réponse ICMP non pris en charge pour le port : %d\n", port);
                    break;
            }
        }
    }
    // Cas des paquets UDP - Si une réponse UDP valide est capturée, marquer le port comme "OPEN"
    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ihl * 4);
        int port = ntohs(udph->source);  // Utilise le port source de la réponse UDP pour identifier le port cible scanné
        printf("Réponse UDP détectée pour le port : %d\n", port);

        // Mettre à jour le statut du port en "OPEN" si réponse UDP reçue
        if (port > 0 && port <= MAX_PORT) {
            printf("HELOOOO\n");
            strcpy(options->status[0][port - 1], "OPEN");
        }
    }
}

pcap_t *init_pcap_udp(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (getuid() != 0) {
        fprintf(stderr, "You need to be root to run this program\n");
        exit(1);
    }

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface: %s\n", errbuf);
        exit(1);
    }

    // Appliquer un filtre BPF pour capturer les paquets TCP ou ICMP
    struct bpf_program fp;
    char filter_exp[] = "icmp or udp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling BPF filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting BPF filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(1);
    }

    pcap_freecode(&fp);  // Libérer la mémoire du filtre BPF

    return handle;
}

// void wait_for_responses_udp(pcap_t *handle, ScanOptions *options) {
//     global_handle_udp = handle;

//     // Définir un timeout (exemple: 15 secondes)
//     signal(SIGALRM, timeout_handler_udp);
//     alarm(5);  // Timeout de 15 secondes

//     // Capture des paquets en boucle jusqu'à expiration du délai
//     while (!stop_pcap_udp) {
//         printf("cdcdcdcdc\n");
//         pcap_dispatch(handle, -1, packet_handler_udp, (u_char *)options);
//     }

//     // Réinitialiser et fermer pcap
//     alarm(5);
//     global_handle_udp = NULL;
// }
void wait_for_responses_udp(pcap_t *handle, ScanOptions *options) {
    global_handle_udp = handle;

    // Définir un timeout (exemple: 15 secondes)
    signal(SIGALRM, timeout_handler_udp);
    alarm(15);  // Timeout de 15 secondes

    int res;
    while (!stop_pcap_udp) {
        printf("Attente de paquets...\n");  // Log supplémentaire

        res = pcap_dispatch(handle, -1, packet_handler_udp, (u_char *)options);
        
        if (res == -1) {
            fprintf(stderr, "Erreur dans pcap_dispatch : %s\n", pcap_geterr(handle));
            break;
        } else if (res == 0) {
            printf("Aucun paquet capturé dans ce cycle...\n");  // Aucun paquet capturé
        } else {
            printf("Nombre de paquets capturés : %d\n", res);  // Nombre de paquets capturés
        }
    }

    alarm(2);  // Arrêter l'alarme si la boucle se termine
    global_handle_udp = NULL;
}


void udp_scan_all_ports(ScanOptions *options) {
    int sock = create_udp_socket();
    struct sockaddr_in dest;
    char packet[4096];  // Buffer pour le paquet
    pcap_t *handle = init_pcap_udp(options->local_interface);

    // Configurer l'adresse de destination
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    struct iphdr *iph = (struct iphdr *)packet;
    build_ip_header_udp(iph, &dest, options);

    // Construire et envoyer les paquets UDP sur les ports spécifiés
    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];
        dest.sin_port = htons(target_port);

        // Nettoyer le paquet
        memset(packet, 0, 4096);

        // Construire les en-têtes IP et UDP
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

        build_udp_header_udp(udph, target_port);

        // Envoyer le paquet personnalisé
        if (sendto(sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Failed to send UDP packet");
        }

        
        // Petit délai entre les envois pour éviter de saturer le réseau
        usleep(1000);
    }

    // Attendre les réponses ICMP
    
    wait_for_responses_udp(handle, options);

    // Fermer le socket et l'interface pcap après la capture des réponses
    close(sock);
    pcap_close(handle);
}
