#include "ft_nmap.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *threaded_scan(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;
    ScanOptions *options = data->options;

    printf("Thread %d: start_scan=%d, end_scan=%d\n", data->thread_id, data->start_scan, data->end_scan);

    // Crée un socket local
    // int sock = create_raw_socket();
    // int optval = 1;
    // if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
    //     perror("Error setting IP_HDRINCL");
    //     pthread_exit(NULL);
    // }

    // Crée un handle pcap local
    // pcap_t *handle = init_pcap(options->local_interface);
    // Prépare un buffer de paquet local
    // char packet[4096];
    // struct iphdr *iph = (struct iphdr *)packet;
    // struct sockaddr_in dest;
    // dest.sin_family = AF_INET;
    // dest.sin_addr.s_addr = inet_addr(options->ip_address);

    pthread_mutex_lock(&mutex);
    // build_ip_header(iph, &dest, options);
    int sock = data->sock;
    // pcap_t *handle = data->handle;
    char *packet = data->packet;
    struct iphdr *iph = data->iph;
    struct sockaddr_in dest = data->dest;

    // Boucle sur les scans assignés
    if (data->start_scan == data->end_scan) {
        int scan = data->start_scan;
        options->currentScan = scan;
        options->scan_type = options->tabscan[scan];
        printf("TTTTTThread %d: Performing scan %d of type %d\n", data->thread_id, scan, options->scan_type);
        // Boucle sur les ports
        stop_pcap = false;
        for (int port_idx = data->start_port; port_idx < data->end_port; port_idx++) {
            int target_port = options->portsTab[port_idx];
            dest.sin_port = htons(target_port);
            

            build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
            send_packet(sock, packet, iph, &dest);
            usleep(1000);
        }

        // wait_for_responses(handle, options);
        printf("Thread %d: Finished scan %d\n", data->thread_id, scan);
    } else {
        for (int scan = data->start_scan; scan < data->end_scan; scan++) {
            // Synchronisation pour les modifications partagées
            options->currentScan = scan;
            options->scan_type = options->tabscan[scan];
            
            printf("Thread %d: Performing scan %d of type %d\n", data->thread_id, scan, options->scan_type);

            // Boucle sur les ports
            stop_pcap = false;
            for (int port_idx = data->start_port; port_idx < data->end_port; port_idx++) {
                // printf("yo\n");
                int target_port = options->portsTab[port_idx];
                dest.sin_port = htons(target_port);

                // Construire et envoyer le paquet
                build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
                // pthread_mutex_lock(&mutex);
                send_packet(sock, packet, iph, &dest);
                // pthread_mutex_unlock(&mutex);
                usleep(1000); // Délai pour éviter la saturation réseau
                
            }

            // Attendre les réponses pour ce scan
            // pthread_mutex_lock(&mutex);
            // wait_for_responses(handle, options);
            // pthread_mutex_unlock(&mutex);
            // usleep(1000); // Délai pour éviter les interférences entre scans
            printf("Thread %d: Finished scan %d\n", data->thread_id, scan);
        }
    }

    // Libération des ressources locales
    // close(sock);
    // pcap_close(handle);
    pthread_mutex_unlock(&mutex);

    printf("Thread %d: Finished all scans.\n", data->thread_id);
    pthread_exit(NULL);
    return NULL;
}

void run_scans_by_techniques(ScanOptions *options) {
    int num_threads = options->speedup; // Nombre de threads demandé
    pthread_t threads[num_threads];
    ScanThreadData thread_data[num_threads];

    // Initialisation commune
    int sock = create_raw_socket();
    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    pcap_t *handle = init_pcap(options->local_interface);
    char *packet = malloc(4096);
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    build_ip_header(iph, &dest, options);

    // Total de combinaisons (scans x ports)
    int total_combinations = options->scan_count * options->portsTabSize;
    int combinations_per_thread = total_combinations / num_threads;
    int extra_combinations = total_combinations % num_threads;

    int current_combination = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].options = options;

        // Partager les ressources initialisées
        thread_data[i].sock = sock;
        thread_data[i].handle = handle;
        thread_data[i].packet = packet;
        thread_data[i].iph = iph;
        thread_data[i].dest = dest;

        // Calculer les combinaisons (scan, port) pour ce thread
        int start_combination = current_combination;
        int end_combination = start_combination + combinations_per_thread + (i < extra_combinations ? 1 : 0);
        current_combination = end_combination;

        thread_data[i].start_scan = start_combination / options->portsTabSize;
        thread_data[i].end_scan = end_combination / options->portsTabSize;
        thread_data[i].start_port = start_combination % options->portsTabSize;
        thread_data[i].end_port = end_combination % options->portsTabSize;

        // Cas particulier pour le premier scan : séparation des ports
        if (thread_data[i].start_scan == 0 && thread_data[i].end_scan == 1) {
            int ports_per_thread = options->portsTabSize / (num_threads / options->scan_count);
            thread_data[i].start_port = (i % (num_threads / options->scan_count)) * ports_per_thread;
            thread_data[i].end_port = thread_data[i].start_port + ports_per_thread;
        }

        // Ajuster les ports si le thread couvre une technique entière
        if (thread_data[i].start_scan != thread_data[i].end_scan) {
            thread_data[i].start_port = 0;               // Début des ports
            thread_data[i].end_port = options->portsTabSize; // Fin des ports
        }

        printf("Thread %d: scans [%d, %d), ports [%d, %d)\n",
               i, thread_data[i].start_scan, thread_data[i].end_scan,
               thread_data[i].start_port, thread_data[i].end_port);

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
    wait_for_responses(handle, options);
    // Libération des ressources partagées
    close(sock);
    pcap_close(handle);
    free(packet);
}



