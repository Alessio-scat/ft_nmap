#include "ft_nmap.h"

pcap_t *global_handle = NULL;
bool stop_pcap = false;

void timeout_handler(int signum) {
    if (signum == SIGALRM) {
        stop_pcap = true;
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
    char filter_exp[] = "tcp or icmp or udp";
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
    global_handle = handle;
    return handle;
}

void wait_for_responses(pcap_t *handle, ScanOptions *options) {
    global_handle = handle;
    stop_pcap = false;
    // Définir un timeout (exemple: 15 secondes)
    signal(SIGALRM, timeout_handler);
    alarm(5);  // Timeout de 15 secondes
    // printf("ici\n");
    // Capture des paquets en boucle jusqu'à expiration du délai
    while (!stop_pcap) {
        // printf("sdfsdfsdfsdfsdfsdf\n");
        pcap_dispatch(handle, -1, packet_handler, (u_char *)options);
    }
    

    // Réinitialiser et fermer pcap
    // alarm(0);
    global_handle = NULL;
}

void tcp_scan_all_ports(ScanOptions *options) {
    int sock; // Declare `sock` at the beginning of the function
    // Initialize pcap once for capturing responses
    // pcap_t *handle = init_pcap(options->local_interface);

    // Prepare the packet
    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));

    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);
    // Loop through each scan type
    for (int i = 0; i < options->scan_count; i++) {
        stop_pcap = false;
        options->currentScan = i;
        options->scan_type = options->tabscan[i];
        // printf("%d %d %d\n", options->scan_type, options->start_scan, options->end_scan);

        // Create appropriate socket and build packet headers
        if (options->scan_type == 6) {
            sock = create_udp_socket(); // Use UDP socket for type 6 scans

            memset(packet, 0, sizeof(packet)); // Netooyer le buffer

            build_ip_header_udp(iph, &dest, options);
        } else {
            sock = create_raw_socket(); // Use raw socket for other scan types
            build_ip_header(iph, &dest, options);
        }

        // Send packets for the current scan type
        send_all_packets(sock, packet, iph, &dest, options);

        // Wait for responses for the current scan type

        // Optional: Add a short delay between scans
        close(sock);
    }

    // wait_for_responses(handle, options);
    // // Close the raw/UDP socket and pcap after all scans
    // pcap_close(handle);
}
