#include "ft_nmap.h"
pcap_t *global_handle = NULL;

int create_raw_socket();
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options);
void build_tcp_header(struct tcphdr *tcph, int target_port);
void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest);

void timeout_handler(int signum) {
    if (signum == SIGALRM) {
        // printf("Timeout atteint. Le port est probablement filtré.\n");
        if (global_handle) {
            pcap_breakloop(global_handle);  // Arrêter la capture
        }
    }
}

// void print_tcphdr(struct tcphdr *tcph) {
//     printf("=== En-tête TCP ===\n");
//     printf("Source Port: %d\n", ntohs(tcph->source));        // Port source
//     printf("Destination Port: %d\n", ntohs(tcph->dest));      // Port destination
//     printf("Sequence Number: %u\n", ntohl(tcph->seq));        // Numéro de séquence
//     printf("Acknowledgment Number: %u\n", ntohl(tcph->ack_seq));  // Numéro d'accusé de réception
//     printf("Data Offset: %d\n", tcph->doff * 4);              // Longueur de l'en-tête TCP
//     printf("Flags: \n");
//     printf("   SYN: %d\n", tcph->syn);                        // Flag SYN
//     printf("   ACK: %d\n", tcph->ack);                        // Flag ACK
//     printf("   RST: %d\n", tcph->rst);                        // Flag RST
//     printf("   FIN: %d\n", tcph->fin);                        // Flag FIN
//     printf("   PSH: %d\n", tcph->psh);                        // Flag PSH
//     printf("   URG: %d\n", tcph->urg);                        // Flag URG
//     printf("Window Size: %d\n", ntohs(tcph->window));         // Taille de la fenêtre
//     printf("Checksum: 0x%x\n", ntohs(tcph->check));           // Checksum TCP
//     printf("Urgent Pointer: %d\n", tcph->urg_ptr);            // Pointeur urgent
//     printf("===================\n");
// }

int create_raw_socket() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Error creating raw socket");
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
void build_tcp_header(struct tcphdr *tcph, int target_port) {
    tcph->source = htons(rand() % 65535 + 1024);  // Port source aléatoire
    tcph->dest = htons(target_port);  // Port cible
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // Longueur de l'en-tête TCP
    tcph->syn = 1;   // Flag SYN activé
    tcph->fin = 0;   // Flag FIN désactivé
    tcph->rst = 0;   // Flag RST désactivé
    tcph->psh = 0;   // Flag PSH désactivé
    tcph->urg = 0;   // Flag URG désactivé
    tcph->ack = 0;   // Flag ACK désactivé
    tcph->window = htons(5840);  // Taille de la fenêtre TCP
    tcph->check = 0;  // Le checksum sera calculé plus tard
    tcph->urg_ptr = 0;  // Pointeur urgent désactivé
}


void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest) {
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Déclare et initialise le pseudo-header pour le calcul du checksum
    psh pshdr;
    pshdr.source_address = iph->saddr; // Adresse IP source
    pshdr.dest_address = iph->daddr; // Adresse IP destination
    pshdr.placeholder = 0; // Champ de remplissage
    pshdr.protocol = IPPROTO_TCP; // Protocole TCP
    pshdr.tcp_length = htons(sizeof(struct tcphdr)); // Longueur de l'en-tête TCP

    // Taille totale pour le calcul du checksum (pseudo-header + en-tête TCP)
    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    // Copier le pseudo-header et l'en-tête TCP dans le buffer pour le calcul
    memcpy(pseudogram, (char *)&pshdr, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));

    // Calculer le checksum TCP en utilisant le pseudo-header et l'en-tête TCP
    tcph->check = checksum((unsigned short *)pseudogram, psize);

    // printf("Envoi d'un paquet SYN vers %s:%d\n", inet_ntoa(dest->sin_addr), ntohs(tcph->dest));

    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("Échec de l'envoi du paquet");
    }

    usleep(1000);
    free(pseudogram);
}

// Fonction de capture des paquets pour vérifier la réponse SYN-ACK ou RST
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;

    pcap_data_t *data = (pcap_data_t *)user_data;
    struct iphdr *iph = (struct iphdr *)(packet + 14); // Sauter l'en-tête Ethernet (14 octets)
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4); // Sauter l'en-tête IP

    int target_port = data->target_port;

    if (iph->protocol == IPPROTO_TCP && ntohs(tcph->source) == target_port) {
        if (tcph->syn == 1 && tcph->ack == 1) {
            // Port ouvert
            // printf("Port %d est ouvert (SYN-ACK reçu)\n", target_port);
            data->port_status = PORT_OPEN;
        } else if (tcph->rst == 1) {
            // Port fermé
            // printf("Port %d est fermé (RST reçu)\n", target_port);
            data->port_status = PORT_CLOSED;
        }
        pcap_breakloop(data->pcap_handle);  // Arrêter la capture une fois qu'une réponse est reçue
    }
}

int receive_response_pcap(ScanOptions *options, int target_port) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Ouvrir l'interface pour capturer les paquets
    handle = pcap_open_live(options->local_interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Impossible d'ouvrir l'interface : %s\n", errbuf);
        return PORT_FILTERED;
    }

    // Mettre à jour le handle global pour le gestionnaire de timeout
    global_handle = handle;

    // Préparer les données pour passer à packet_handler
    pcap_data_t pcap_data;
    pcap_data.pcap_handle = handle;
    pcap_data.target_port = target_port;
    pcap_data.port_status = PORT_FILTERED;  // Par défaut, on considère le port comme filtré

    struct bpf_program fp;
    char filter_exp[50];
    sprintf(filter_exp, "tcp and src port %d", target_port);  // Capture les paquets TCP du port cible

    // Compiler et appliquer le filtre BPF
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Erreur de compilation du filtre : %s\n", pcap_geterr(handle));
        return PORT_FILTERED;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Erreur d'application du filtre : %s\n", pcap_geterr(handle));
        return PORT_FILTERED;
    }

    // Définir un timeout de 3 secondes
    signal(SIGALRM, timeout_handler);
    alarm(3);  // Timeout après 3 secondes

    // Commencer la capture de paquets
    pcap_loop(handle, 10, packet_handler, (u_char *)&pcap_data);


    // Arrêter l'alarme si pcap_loop a terminé avant le timeout
    alarm(0);

    // Fermer le handle de capture
    pcap_close(handle);
    
    // Réinitialiser le handle global pour éviter des erreurs futures
    global_handle = NULL;

    // Retourner l'état du port
    return pcap_data.port_status;
}


void syn_scan_all_ports(ScanOptions *options) {
    printf("Results for %s\n", options->ip_address);
    printf("SYN     PORT    SERVICE         STATE\n");

    int sock = create_raw_socket();  // Créer le socket brut une seule fois
    int optval = 1;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    char packet[4096];  // Réutilisation du même buffer pour chaque port
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;

    // Configurer l'adresse de destination (IP ne change pas pour chaque port)
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Construire l'en-tête IP une seule fois
    build_ip_header(iph, &dest, options);

    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];
        
        // Configurer le port de destination pour chaque port
        dest.sin_port = htons(target_port);

        // Construire l'en-tête TCP pour chaque port
        build_tcp_header(tcph, target_port);

        // Envoyer le paquet SYN
        send_packet(sock, packet, iph, &dest);

        // Recevoir la réponse pour ce port
        int port_status = receive_response_pcap(options, target_port);

        // Nom du service
        struct servent *service_entry = getservbyport(htons(target_port), "tcp");
        const char *service_name = (service_entry != NULL) ? service_entry->s_name : "unknown";

        // Afficher l'état du port selon le résultat
        if (port_status == PORT_OPEN) {
            print_scan_result(target_port, service_name, "OPEN");
        } else if (port_status == PORT_FILTERED) {
            print_scan_result(target_port, service_name, "FILTERED");
        } else {
            print_scan_result(target_port, service_name, "CLOSED");
        }

        // Petit délai entre les scans
        usleep(50000);
    }

    // Fermer le socket brut après avoir terminé le scan
    close(sock);
}


