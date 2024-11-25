#include "ft_nmap.h"

void *scan_technique_thread(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;

    // Préparer le paquet
    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(data->options->ip_address);

    // Construire l'en-tête IP
    build_ip_header(iph, &dest, data->options);

    // Définir la technique de scan pour ce thread
    data->options->scan_type = data->scan_type;

    printf("Thread %d exécutant le scan de type %d\n", data->thread_id, data->scan_type);

    // Envoyer les paquets pour ce type de scan
    send_all_packets(data->sock, packet, iph, &dest, data->options);

    // Capturer les réponses pour ce type de scan
    wait_for_responses(data->handle, data->options);
    
    printf("aaaaaaaaaaaaaaaaaaaaa\n");
    pthread_exit(NULL);
}


void run_scans_by_techniques(ScanOptions *options) {
    int num_techniques = options->scan_count; // Nombre de techniques de scan
    pthread_t threads[num_techniques];
    ScanThreadData thread_data[num_techniques];

    // Créer le socket brut une seule fois
    int sock = create_raw_socket();
    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    // Initialiser pcap une seule fois
    pcap_t *handle = init_pcap(options->local_interface);

    // Créer un thread pour chaque technique
    for (int i = 0; i < num_techniques; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].scan_type = options->tabscan[i]; // Type de scan
        thread_data[i].currentScan = i;                // Assignation unique
        thread_data[i].options = options;
        thread_data[i].sock = sock;
        thread_data[i].handle = handle;

        // Créer le thread
        if (pthread_create(&threads[i], NULL, scan_technique_thread, &thread_data[i]) != 0) {
            perror("Failed to create thread");
            exit(1);
        }
    }

    // Attendre que tous les threads terminent
    for (int i = 0; i < num_techniques; i++) {
        pthread_join(threads[i], NULL);
    }

    // Nettoyer les ressources
    close(sock);
    pcap_close(handle);
}

