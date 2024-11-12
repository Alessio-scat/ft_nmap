#include "ft_nmap.h"

pcap_t *global_handle_udp = NULL;
bool stop_pcap_udp = false;

void build_ip_header_udp(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr)); // Taille IP + UDP
    iph->id = htonl(54321); // ID unique
    iph->frag_off = 0;
    iph->ttl = 64;  // TTL standard
    iph->protocol = IPPROTO_UDP;  // Protocole UDP
    iph->check = 0;  // Checksum sera calculé après
    iph->saddr = inet_addr(options->local_ip);  // Adresse source (locale)
    iph->daddr = dest->sin_addr.s_addr;

    // Calcul du checksum pour l'en-tête IP
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
}

void build_udp_header_udp(struct udphdr *udph, int target_port) {
    udph->source = htons(rand() % 65535 + 1024);  // Port source aléatoire
    udph->dest = htons(target_port);  // Port cible
    udph->len = htons(sizeof(struct udphdr));  // Longueur de l'en-tête UDP
    udph->check = 0;  // Checksum UDP (optionnel pour IPv4, peut être laissé à 0)
}



void timeout_handler_udp(int signum) {
    if (signum == SIGALRM) {
        stop_pcap_udp = true;  // Mettre stop_pcap_udp à true pour arrêter la boucle
        if (global_handle_udp) {
            pcap_breakloop(global_handle_udp);  // Arrêter la capture pcap
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

void packet_handler_udp(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;
    ScanOptions *options = (ScanOptions *)user_data;

    struct iphdr *iph = (struct iphdr *)(packet + 14); // En-tête IP après l'en-tête Ethernet
    int protocol = iph->protocol;
    printf("je passe\n");
    if (protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)(packet + 14 + iph->ihl * 4);

        // Vérifie si c'est un message "Port Unreachable"
        if (icmph->type == 3 && icmph->code == 3) {
            printf("TEST - ICMP Port Unreachable reçu\n");

            // Se déplacer jusqu'à l'en-tête UDP encapsulé dans le message ICMP
            // iph->ihl est en nombre de mots de 32 bits, donc on multiplie par 4 pour obtenir des octets
            struct iphdr *inner_iph = (struct iphdr *)(packet + 14 + iph->ihl * 4 + sizeof(struct icmphdr));
            int inner_ip_header_length = inner_iph->ihl * 4;

            // Calculer le début de l'en-tête UDP dans le paquet ICMP
            struct udphdr *udph = (struct udphdr *)((u_char *)inner_iph + inner_ip_header_length);
            int port = ntohs(udph->dest);
            printf("Port détecté : %d, Max autorisé : %d\n", port, MAX_PORT);

            // Vérifie si le port est dans la plage autorisée
            if (port > 0 && port <= MAX_PORT) {
                printf("Port %d marqué comme CLOSED\n", port);
                strcpy(options->status[0][port - 1], "CLOSED");
            }
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
    char filter_exp[] = "icmp";  // Filtre pour capturer les paquets TCP et ICMP
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
    printf("Interface %s ouverte avec un filtre TCP et ICMP.\n", interface);

    return handle;
}

void wait_for_responses_udp(pcap_t *handle, ScanOptions *options) {
    global_handle_udp = handle;

    // Définir un timeout (exemple: 15 secondes)
    signal(SIGALRM, timeout_handler_udp);
    alarm(15);  // Timeout de 15 secondes

    // Capture des paquets en boucle jusqu'à expiration du délai
    while (!stop_pcap_udp) {
        pcap_dispatch(handle, -1, packet_handler_udp, (u_char *)options);
    }

    // Réinitialiser et fermer pcap
    alarm(15);
    global_handle_udp = NULL;
}


void udp_scan_all_ports(ScanOptions *options) {
    int sock = create_udp_socket();
    struct sockaddr_in dest;
    char packet[4096];  // Buffer pour le paquet

    // Configurer l'adresse de destination
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Construire et envoyer les paquets UDP sur les ports spécifiés
    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];
        dest.sin_port = htons(target_port);

        // Nettoyer le paquet
        memset(packet, 0, 4096);

        // Construire les en-têtes IP et UDP
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

        build_ip_header_udp(iph, &dest, options);
        build_udp_header_udp(udph, target_port);

        // Envoyer le paquet personnalisé
        if (sendto(sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Failed to send UDP packet");
        }
        
        // Petit délai entre les envois pour éviter de saturer le réseau
        usleep(1000);
    }

    // Attendre les réponses ICMP
    pcap_t *handle = init_pcap_udp(options->local_interface);
    wait_for_responses_udp(handle, options);

    // Fermer le socket et l'interface pcap après la capture des réponses
    close(sock);
    pcap_close(handle);
}
