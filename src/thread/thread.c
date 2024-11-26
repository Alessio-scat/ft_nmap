#include "ft_nmap.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *threaded_scan(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;
    ScanOptions *options = data->options;

    printf("Thread %d: start_scan=%d, end_scan=%d\n", data->thread_id, data->start_scan, data->end_scan);

    // Crée un socket local
    int sock = create_raw_socket();
    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        pthread_exit(NULL);
    }

    // Crée un handle pcap local
    pcap_t *handle = init_pcap(options->local_interface);
    // Prépare un buffer de paquet local
    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    build_ip_header(iph, &dest, options);

    // Boucle sur les scans assignés
    pthread_mutex_lock(&mutex);
    for (int scan = data->start_scan; scan < data->end_scan; scan++) {
        // Synchronisation pour les modifications partagées
        options->currentScan = scan;
        options->scan_type = options->tabscan[scan];
        
        printf("Thread %d: Performing scan %d of type %d\n", data->thread_id, scan, options->scan_type);

        // Boucle sur les ports
        for (int port_idx = 0; port_idx < options->portsTabSize; port_idx++) {
            
            stop_pcap = false;
            int target_port = options->portsTab[port_idx];
            dest.sin_port = htons(target_port);

            // Construire et envoyer le paquet
            build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
            send_packet(sock, packet, iph, &dest);
            usleep(1000); // Délai pour éviter la saturation réseau
            
        }

        // Attendre les réponses pour ce scan
        
        wait_for_responses(handle, options);
        sleep(1); // Délai pour éviter les interférences entre scans
        printf("Thread %d: Finished scan %d\n", data->thread_id, scan);
    }

    // Libération des ressources locales
    close(sock);
    pcap_close(handle);
    pthread_mutex_unlock(&mutex);

    printf("Thread %d: Finished all scans.\n", data->thread_id);
    pthread_exit(NULL);
    return NULL;
}

void run_scans_by_techniques(ScanOptions *options) {
    // Réduire le nombre de threads si supérieur au nombre de scans
    int num_threads = options->speedup > options->scan_count ? options->scan_count : options->speedup;
    pthread_t threads[num_threads];
    ScanThreadData thread_data[num_threads];

    // Répartition des techniques (scans)
    int scans_per_thread = options->scan_count / num_threads;
    int extra_scans = options->scan_count % num_threads;

    int current_scan = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].options = options;

        // Répartition des scans
        thread_data[i].start_scan = current_scan;
        thread_data[i].end_scan = current_scan + scans_per_thread + (i < extra_scans ? 1 : 0);
        current_scan = thread_data[i].end_scan;

        printf("Thread %d: scans [%d, %d)\n", i, thread_data[i].start_scan, thread_data[i].end_scan);

        // Créer le thread
        if (pthread_create(&threads[i], NULL, threaded_scan, &thread_data[i]) != 0) {
            perror("Failed to create thread");
            exit(1);
        }
    }

    // Attendre que tous les threads terminent
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        printf("Thread %d joined.\n", i);
    }
}
