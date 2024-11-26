#include "ft_nmap.h"

pcap_t *global_handle = NULL;
volatile bool stop_pcap = false;

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
    char filter_exp[] = "tcp or icmp";
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
    alarm(5);  // Timeout de 15 secondes
    printf("ici\n");
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
        if(options->scan_type == 6){
            udp_scan_all_ports(options);
        }
        else {
        // Envoyer les paquets pour le type de scan actuel
        send_all_packets(sock, packet, iph, &dest, options);

        // Attendre les réponses pour le scan actuel
        wait_for_responses(handle, options);

        // Optionnel : ajouter un délai court entre les scans pour éviter les interférences
        sleep(1);
        }
    }

    // Fermer le socket brut et pcap après tous les scans
    close(sock);
    pcap_close(handle);
}


