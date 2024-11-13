#include "ft_nmap.h"
pcap_t *global_handle = NULL;
bool stop_pcap = false;

int create_raw_socket();
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options);
void build_tcp_header(struct tcphdr *tcph, int target_port, ScanOptions *options);
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
void build_tcp_header(struct tcphdr *tcph, int target_port, ScanOptions *options) {
    tcph->source = htons(rand() % 65535 + 1024);  // Port source aléatoire
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
    tcph->fin = 0;   // Flag FIN désactivé
    tcph->rst = 0;   // Flag RST désactivé
    if (options->scan_type == XMAS){
        tcph->psh = 1;   
        tcph->urg = 1;   
    }
    tcph->psh = 0;   // Flag PSH désactivé
    tcph->urg = 0;   // Flag URG désactivé
    if (options->scan_type == ACK) {
        tcph->ack = 1; 
    }
    else
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
    free(pseudogram);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;

    // Récupération des données utilisateur (ScanOptions)
    ScanOptions *options = (ScanOptions *)user_data;

    // Sauter l'en-tête Ethernet (14 octets)
    struct iphdr *iph = (struct iphdr *)(packet + 14); 
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4); 

    // Vérifier si le paquet provient de l'IP cible
    struct in_addr source_addr;
    source_addr.s_addr = iph->saddr;
    
    if (strcmp(inet_ntoa(source_addr), options->ip_address) != 0) {
        // printf("Paquet ignoré de %s\n", inet_ntoa(source_addr));
        return;
    }
    // Identifier le port cible
    int port = ntohs(tcph->source);  // Port source (ou destination selon ton besoin)
    // Vérifier que le port est dans les limites
    if (port > MAX_PORT || port == 0) {
        return;
    }
    if(options->ttl == 0)
        options->ttl = iph->ttl;
    // printf("TTL de la cible : %d port : %d\n", iph->ttl, port);

    
    // Vérifier si le paquet est un paquet TCP
    if (iph->protocol == IPPROTO_TCP) {
        if (options->scan_type == SYN) {  // Scan SYN
            if (tcph->syn == 1 && tcph->ack == 1) {
                // Port ouvert
                strcpy(options->status[options->currentScan][port - 1], "OPEN");
            } else if (tcph->rst == 1) {
                // Port fermé
                strcpy(options->status[options->currentScan][port - 1], "CLOSED");
            }
        } else if (options->scan_type == SCAN_NULL || options->scan_type == FIN || options->scan_type == XMAS) {  // Scan NULL
            if (tcph->rst == 1) {
                // printf("passe %d\n", port);
                // Port fermé
                strcpy(options->status[options->currentScan][port - 1], "CLOSED");
            } else {
                // printf("yo %d\n", port);
                // Absence de réponse interprétée comme port ouvert ou filtré
                strcpy(options->status[options->currentScan][port - 1], "OPEN|FILTERED");
            }
        } else if (options->scan_type == ACK) {  // Scan ACK
            if (tcph->rst == 1) {
                // Port non filtré
                strcpy(options->status[options->currentScan][port - 1], "UNFILTERED");
            } else {
                // Absence de réponse interprétée comme port filtré
                strcpy(options->status[options->currentScan][port - 1], "FILTERED");
            }
        }
    }
    alarm(2);

    // Tu peux aussi traiter les paquets ICMP ou autres protocoles ici si besoin

    // Ne pas arrêter la capture, car tu veux capturer plusieurs paquets pour plusieurs ports
}


void send_all_packets(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {

    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];
        // printf("%d\n", options->portsTabSize);
        // printf("%d\n", target_port);
        dest->sin_port = htons(target_port);

        // Construire l'en-tête TCP pour chaque port
        build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);

        // Envoyer le paquet SYN
        send_packet(sock, packet, iph, dest);

        // Petit délai entre les envois pour ne pas saturer le réseau
        usleep(1000);
    }
}

#include <pcap.h>

pcap_t *init_pcap(const char *interface) {
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

    // Appliquer un filtre BPF pour capturer uniquement les paquets TCP
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // Filtre pour capturer les paquets TCP
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
    printf("Interface %s ouverte avec un filtre TCP.\n", interface);

    return handle;
}

void wait_for_responses(pcap_t *handle, ScanOptions *options) {
    global_handle = handle;

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

void tcp_scan_all_ports(ScanOptions *options) {
    // Créer le socket brut une seule fois
    int sock = create_raw_socket();
    int optval = 1;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    // Initialiser pcap une seule fois pour capturer les réponses
    pcap_t *handle = init_pcap(options->local_interface);

    // Préparer le paquet
    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Construire l'en-tête IP une fois (valide pour les deux scans)
    build_ip_header(iph, &dest, options);

    // Boucle interne pour exécuter chaque type de scan
    for (int i = 0; i < options->scan_count; i++) {
        stop_pcap = false;
        options->currentScan = i;
        options->scan_type = options->tabscan[i];

        // Envoyer les paquets pour le type de scan actuel
        send_all_packets(sock, packet, iph, &dest, options);

        // Attendre les réponses pour le scan actuel
        wait_for_responses(handle, options);

        // Optionnel : ajouter un délai court entre les scans pour éviter les interférences
        sleep(1);
    }

    // Fermer le socket brut et pcap après tous les scans
    close(sock);
    pcap_close(handle);
}


