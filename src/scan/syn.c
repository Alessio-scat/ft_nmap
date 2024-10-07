#include "ft_nmap.h"
pcap_t *global_handle = NULL;
bool stop_pcap = false;

int create_raw_socket();
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options);
void build_tcp_header(struct tcphdr *tcph, int target_port);
void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest);

void timeout_handler(int signum) {
    if (signum == SIGALRM) {
        stop_pcap = true;
        // printf("Timeout atteint. Le port est probablement filtré.\n");
        if (global_handle) {
            pcap_breakloop(global_handle);  // Arrêter la capture
        }
    }
}

int create_raw_socket(int protocole, int i) {
    int sockfd = socket(AF_INET, i, protocole);
    if (sockfd < 0) {
        perror("Error creating raw socket");
        exit(1);
    }
    return sockfd;
}


void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest) {
    // On récupère le protocole du paquet
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    (void)udph;

    if (iph->protocol == IPPROTO_TCP) {
        printf("Envoi d'un paquet TCP...\n");        psh pshdr;
        pshdr.source_address = iph->saddr; // Adresse IP source
        pshdr.dest_address = iph->daddr; // Adresse IP destination
        pshdr.placeholder = 0; // Champ de remplissage
        pshdr.protocol = IPPROTO_TCP; // Protocole TCP
        pshdr.tcp_length = htons(sizeof(struct tcphdr)); // Longueur de l'en-tête TCP

        int psize = sizeof(psh) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);

        memcpy(pseudogram, (char *)&pshdr, sizeof(psh));
        memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));

        tcph->check = checksum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
            perror("Échec de l'envoi du paquet TCP");
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        printf("Envoi d'un paquet UDP...\n");
        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
            perror("Échec de l'envoi du paquet UDP");
        }
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;

    // Récupération des données utilisateur (ScanOptions)
    ScanOptions *options = (ScanOptions *)user_data;

    // Sauter l'en-tête Ethernet (14 octets)
    struct iphdr *iph = (struct iphdr *)(packet + 14); 
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4);
    struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ihl * 4); 

    // Identifier le port cible
    int port = 0;
    if (iph->protocol == IPPROTO_TCP) {
        port = ntohs(tcph->source);
    } else if (iph->protocol == IPPROTO_UDP) {
        port = ntohs(udph->source);
    }

    // Vérifier que le port est dans les limites
    if (port > MAX_PORT || port == 0) {
        return;
    }

    int technique = 0; // Identifier la technique utilisée

    if (iph->protocol == IPPROTO_TCP) {
        if (tcph->syn == 1 && tcph->ack == 1) {
            printf("Port %d: OPEN\n", port);
            strcpy(options->status[technique][port - 1], "OPEN");
        } else if (tcph->rst == 1) {
            printf("Port %d: CLOSED\n", port);
            strcpy(options->status[technique][port - 1], "CLOSED");
        }
    } else {
        // Vérifier les réponses UDP
        printf("ZZZZZZZZZZZZZZZZZZZZ\n");
        if (iph->protocol == IPPROTO_ICMP) {
            printf("Port %d: CLOSED (ICMP response)\n", port);
            strcpy(options->status[technique][port - 1], "CLOSED");
        } else {
            printf("Port %d: OPEN (UDP response)\n", port);
            strcpy(options->status[technique][port - 1], "OPEN");
        }
    }
}


void send_all_packets(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    printf("Sending packets...\n");

    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];
        dest->sin_port = htons(target_port);

        // Construire l'en-tête TCP ou UDP
        if (strcmp(options->scan_type, "SYN") == 0) {
            build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port);
            iph->protocol = IPPROTO_TCP;  // Protocole TCP
        } else if (strcmp(options->scan_type, "UDP") == 0) {
            build_udp_header((struct udphdr *)(packet + sizeof(struct iphdr)), target_port);
            iph->protocol = IPPROTO_UDP;  // Protocole UDP
        }

        // Envoyer le paquet
        send_packet(sock, packet, iph, dest);

        // Petit délai entre les envois pour ne pas saturer le réseau
        usleep(1000);
    }
}

pcap_t *init_pcap(const char *interface, const char *scan_type) {
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

    // Appliquer un filtre BPF en fonction du type de scan
    struct bpf_program fp;
    char filter_exp[30];  // Taille suffisante pour le filtre

    if (strcmp(scan_type, "SYN") == 0) {
        strcpy(filter_exp, "tcp");  // Filtre pour capturer les paquets TCP
    } else if (strcmp(scan_type, "UDP") == 0) {
        strcpy(filter_exp, "udp");  // Filtre pour capturer les paquets UDP
    } else {
        fprintf(stderr, "Unsupported scan type: %s\n", scan_type);
        pcap_close(handle);
        exit(1);
    }

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
    printf("Interface %s ouverte avec un filtre %s.\n", interface, filter_exp);

    return handle;
}


void wait_for_responses(pcap_t *handle, ScanOptions *options) {
    global_handle = handle;

    printf("Waiting for responses...\n");

    // Définir un timeout (exemple: 15 secondes)
    signal(SIGALRM, timeout_handler);
    alarm(15);  // Timeout de 15 secondes

    // Capture des paquets en boucle jusqu'à expiration du délai
    while (!stop_pcap) {
        pcap_dispatch(handle, -1, packet_handler, (u_char *)options);
    }

    // Réinitialiser et fermer pcap
    alarm(0);
    global_handle = NULL;
}

void syn_scan_all_ports(ScanOptions *options) {
    int sock = 0;  // Socket pour TCP
    int sock_udp = 0; // Socket pour UDP
    int optval = 1;
    pcap_t *handle = init_pcap(options->local_interface, options->scan_type);

    // Créer le socket brut en fonction du type de scan
    if (strcmp(options->scan_type, "UDP") == 0) {
        sock_udp = create_raw_socket(IPPROTO_UDP, SOCK_DGRAM); // Créer le socket brut pour UDP
        // if (setsockopt(sock_udp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        //     perror("Error setting IP_HDRINCL");
        //     exit(1);
        // }
    } else {
        sock = create_raw_socket(IPPROTO_TCP, SOCK_RAW);  // Créer le socket brut pour TCP
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
            perror("Error setting IP_HDRINCL");
            exit(1);
        }
    }

    char packet[4096];  // Réutilisation du même buffer pour chaque port
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;

    // Configurer l'adresse de destination (IP ne change pas pour chaque port)
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Construire l'en-tête IP une seule fois
    build_ip_header(iph, &dest, options);

    // Envoyer tous les paquets en fonction du type de scan
    if (strcmp(options->scan_type, "SYN") == 0) {
        // Envoyer tous les paquets SYN
        send_all_packets(sock, packet, iph, &dest, options);
    } else if (strcmp(options->scan_type, "UDP") == 0) {
        // Envoyer tous les paquets UDP
        send_all_packets(sock_udp, packet, iph, &dest, options);
    }

    // Attendre et capturer toutes les réponses en passant le handle pcap à la fonction
    wait_for_responses(handle, options);

    // Fermer les sockets après avoir terminé l'envoi
    if (strcmp(options->scan_type, "SYN") == 0) {
        close(sock);
    } else if (strcmp(options->scan_type, "UDP") == 0) {
        close(sock_udp);
    }

    // Fermer l'interface pcap après avoir capturé les réponses
    pcap_close(handle);
}

