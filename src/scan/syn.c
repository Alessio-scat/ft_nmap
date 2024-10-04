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

void print_tcphdr(struct tcphdr *tcph) {
    printf("=== En-tête TCP ===\n");
    printf("Source Port: %d\n", ntohs(tcph->source));        // Port source
    printf("Destination Port: %d\n", ntohs(tcph->dest));      // Port destination
    printf("Sequence Number: %u\n", ntohl(tcph->seq));        // Numéro de séquence
    printf("Acknowledgment Number: %u\n", ntohl(tcph->ack_seq));  // Numéro d'accusé de réception
    printf("Data Offset: %d\n", tcph->doff * 4);              // Longueur de l'en-tête TCP
    printf("Flags: \n");
    printf("   SYN: %d\n", tcph->syn);                        // Flag SYN
    printf("   ACK: %d\n", tcph->ack);                        // Flag ACK
    printf("   RST: %d\n", tcph->rst);                        // Flag RST
    printf("   FIN: %d\n", tcph->fin);                        // Flag FIN
    printf("   PSH: %d\n", tcph->psh);                        // Flag PSH
    printf("   URG: %d\n", tcph->urg);                        // Flag URG
    printf("Window Size: %d\n", ntohs(tcph->window));         // Taille de la fenêtre
    printf("Checksum: 0x%x\n", ntohs(tcph->check));           // Checksum TCP
    printf("Urgent Pointer: %d\n", tcph->urg_ptr);            // Pointeur urgent
    printf("===================\n");
}

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
// void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
//     (void)pkthdr;

//     pcap_data_t *data = (pcap_data_t *)user_data;
//     struct iphdr *iph = (struct iphdr *)(packet + 14); // Sauter l'en-tête Ethernet (14 octets)
//     struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4); // Sauter l'en-tête IP

//     int target_port = data->target_port;

//     if (iph->protocol == IPPROTO_TCP && ntohs(tcph->source) == target_port) {
//         if (tcph->syn == 1 && tcph->ack == 1) {
//             // Port ouvert
//             // printf("Port %d est ouvert (SYN-ACK reçu)\n", target_port);
//             data->port_status = PORT_OPEN;
//         } else if (tcph->rst == 1) {
//             // Port fermé
//             // printf("Port %d est fermé (RST reçu)\n", target_port);
//             data->port_status = PORT_CLOSED;
//         }
//         pcap_breakloop(data->pcap_handle);  // Arrêter la capture une fois qu'une réponse est reçue
//     }
// }

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;

    // Récupération des données utilisateur (ScanOptions)
    ScanOptions *options = (ScanOptions *)user_data;

    // Sauter l'en-tête Ethernet (14 octets)
    struct iphdr *iph = (struct iphdr *)(packet + 14); 
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4); 

    // Identifier le port cible
    int port = ntohs(tcph->source);  // Port source (ou destination selon ton besoin)

    // Vérifier que le port est dans les limites
    if (port > MAX_PORT || port == 0) {
        // printf("Port out of bounds: %d\n", port);
        return;
    }

    // Identifier la technique utilisée (par exemple SYN scan)
    int technique = 0; // Si tu as plusieurs techniques, tu dois trouver un moyen de l'identifier ici
    // printf("yo %d\n", port);
    // if(port == 22){
    //     print_tcphdr(tcph);
    //     printf("prooo %d %d\n", iph->protocol, IPPROTO_TCP);
    // }
    // Vérifier si le paquet est un paquet TCP
    if (iph->protocol == IPPROTO_TCP) {
        // printf("passssssssssssssssssssseeeeeeeeeeeeeeeeeeee\n");
        if (tcph->syn == 1 && tcph->ack == 1) {
        // printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
            // Port ouvert
            strcpy(options->status[technique][port - 1], "OPEN");
        } else if (tcph->rst == 1) {
            // Port fermé
            strcpy(options->status[technique][port - 1], "CLOSED");
        }
    }
    // printf("yo1\n");


    // Tu peux aussi traiter les paquets ICMP ou autres protocoles ici si besoin

    // Ne pas arrêter la capture, car tu veux capturer plusieurs paquets pour plusieurs ports
}


void send_all_packets(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    printf("Sending packets...\n");

    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];
        // printf("%d\n", options->portsTabSize);
        dest->sin_port = htons(target_port);

        // Construire l'en-tête TCP pour chaque port
        build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port);

        // Envoyer le paquet SYN
        send_packet(sock, packet, iph, dest);

        // Petit délai entre les envois pour ne pas saturer le réseau
        usleep(1000);
    }
}

void wait_for_responses(ScanOptions *options) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Ouvrir l'interface pour capturer les paquets
    handle = pcap_open_live(options->local_interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Impossible d'ouvrir l'interface : %s\n", errbuf);
        return;
    }

    // Mettre à jour le handle global pour le gestionnaire de timeout
    global_handle = handle;

    printf("Waiting for responses...\n");

    // Définir un timeout (exemple: 15 secondes)
    signal(SIGALRM, timeout_handler);
    alarm(15);
    // Commencer la capture des paquets en boucle
    pcap_dispatch(handle, 0, packet_handler, (u_char *)options);

    // Réinitialiser et fermer pcap
    alarm(0);
    pcap_close(handle);
    global_handle = NULL;
}


// void syn_scan_all_ports(ScanOptions *options) {
//     printf("Results for %s\n", options->ip_address);
//     printf("SYN     PORT    SERVICE         STATE\n");

//     int sock = create_raw_socket();  // Créer le socket brut une seule fois
//     int optval = 1;

//     if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
//         perror("Error setting IP_HDRINCL");
//         exit(1);
//     }

//     char packet[4096];  // Réutilisation du même buffer pour chaque port
//     struct iphdr *iph = (struct iphdr *)packet;
//     struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
//     struct sockaddr_in dest;

//     // Configurer l'adresse de destination (IP ne change pas pour chaque port)
//     dest.sin_family = AF_INET;
//     dest.sin_addr.s_addr = inet_addr(options->ip_address);

//     // Construire l'en-tête IP une seule fois
//     build_ip_header(iph, &dest, options);

//     for (int j = 0; j < options->portsTabSize; j++) {
//         int target_port = options->portsTab[j];
        
//         // Configurer le port de destination pour chaque port
//         dest.sin_port = htons(target_port);

//         // Construire l'en-tête TCP pour chaque port
//         build_tcp_header(tcph, target_port);

//         // Envoyer le paquet SYN
//         send_packet(sock, packet, iph, &dest);

//         // Recevoir la réponse pour ce port
//         int port_status = receive_response_pcap(options, target_port);

//         // Nom du service
//         struct servent *service_entry = getservbyport(htons(target_port), "tcp");
//         const char *service_name = (service_entry != NULL) ? service_entry->s_name : "unknown";

//         // Afficher l'état du port selon le résultat
//         if (port_status == PORT_OPEN) {
//             print_scan_result(target_port, service_name, "OPEN");
//         } else if (port_status == PORT_FILTERED) {
//             print_scan_result(target_port, service_name, "FILTERED");
//         } else if (options->flag_ports == 1) {
//             print_scan_result(target_port, service_name, "CLOSED");
//         }

//         // Petit délai entre les scans
//         usleep(1000);
//     }

//     // Fermer le socket brut après avoir terminé le scan
//     close(sock);
// }


void syn_scan_all_ports(ScanOptions *options) {
    // printf("Results for %s\n", options->ip_address);
    // printf("SYN     PORT    SERVICE         STATE\n");

    int sock = create_raw_socket();  // Créer le socket brut une seule fois
    int optval = 1;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    char packet[4096];  // Réutilisation du même buffer pour chaque port
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;

    // Configurer l'adresse de destination (IP ne change pas pour chaque port)
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Construire l'en-tête IP une seule fois
    build_ip_header(iph, &dest, options);

    // Envoyer tous les paquets SYN
    send_all_packets(sock, packet, iph, &dest, options);

    // Fermer le socket brut après avoir terminé l'envoi
    close(sock);

    // Attendre et capturer toutes les réponses
    wait_for_responses(options);
}
