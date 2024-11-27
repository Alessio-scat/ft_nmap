#include "threads.h"
#include "ft_nmap.h"

void *thread_worker(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    ScanOptions *options = data->options;

    // Créer le socket brut pour ce thread
    int sock = create_raw_socket();
    int optval = 1;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        pthread_exit(NULL);
    }

    // Initialiser pcap pour capturer les réponses
    pcap_t *handle = init_pcap(options->local_interface);

    // Préparer le paquet
    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Construire l'en-tête IP une fois
    build_ip_header(iph, &dest, options);

    // Répartir les combinaisons ports x techniques pour ce thread
    for (int i = data->thread_id; i < options->portsTabSize * options->scan_count; i += data->total_threads) {
        int port_index = i % options->portsTabSize;
        int technique_index = i / options->portsTabSize;

        int port = options->portsTab[port_index];
        int scan_type = options->tabscan[technique_index];

        printf("Thread %d scanning port %d with technique %s\n",
               data->thread_id, port, get_scan_name(scan_type));

        // Construire l'en-tête TCP/UDP pour le port actuel
        build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), port, options);

        // Exécuter la logique spécifique au type de scan
        if (scan_type == UDP) {
            udp_scan_all_ports(options);
        } else {
            send_packet(sock, packet, iph, &dest);
            wait_for_responses(handle, options);
        }
    }

    // Fermer les ressources pour ce thread
    close(sock);
    pcap_close(handle);

    pthread_exit(NULL);
}


void init_threads(ScanOptions *options) {
    int total_threads = options->speedup;
    if (total_threads <= 0) {
        fprintf(stderr, "Error: Speedup must be greater than 0.\n");
        exit(EXIT_FAILURE);
    }

    pthread_t threads[total_threads];       // Tableau pour stocker les threads
    ThreadData thread_data[total_threads];  // Données pour chaque thread

    // Créer et démarrer les threads
    for (int i = 0; i < total_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].total_threads = total_threads;
        thread_data[i].options = options;

        // Créer le thread
        if (pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]) != 0) {
            perror("Error creating thread");
            exit(EXIT_FAILURE);
        }
    }

    // Attendre la fin des threads
    for (int i = 0; i < total_threads; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("Error joining thread");
            exit(EXIT_FAILURE);
        }
    }

    printf("All scans completed.\n");
}

