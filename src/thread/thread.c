#include "ft_nmap.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *threaded_scan(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;
    ScanOptions *options = data->options;

    pthread_mutex_lock(&mutex);
    int sock; // Declare `sock` at the beginning of the function
    sock = 1;
    
    char *packet = data->packet;
    struct iphdr *iph = data->iph;
    struct sockaddr_in dest = data->dest;

    // Boucle sur les scans assignés
    for (int scan = data->start_scan; scan < data->end_scan; scan++) {
        // Synchronisation pour les modifications partagées
        stop_pcap = false;
        options->currentScan = scan;
        options->scan_type = options->tabscan[scan];
        if (options->scan_type == 6) {
            sock = create_udp_socket(); // Use UDP socket for type 6 scans
            build_ip_header_udp(iph, &dest, options);
        } else {
            sock = create_raw_socket(); // Use raw socket for other scan types
            build_ip_header(iph, &dest, options);
        }
        for (int j = data->start_port; j < data->end_port; j++) {
            int target_port = options->portsTab[j];

            dest.sin_port = htons(target_port); // Définir le port cible

            if (options->scan_type == UDP) {
                // Initialiser les en-têtes IP et UDP
                memset(packet, 0, 4096); // Nettoyer le buffer
                struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

                build_udp_header_udp(udph, target_port);

                // Envoyer le paquet
                if (sendto(sock, packet, htons(iph->tot_len), 0,
                        (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                    perror("Failed to send UDP packet");
                }
            } else {
                // Construire et envoyer les paquets TCP
                build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
                send_packet(sock, packet, iph, &dest);
            }

            // Petit délai entre les envois
            usleep(1000);
        }
        
    }
    pthread_mutex_unlock(&mutex);
    // printf("Thread %d: Finished all scans.\n", data->thread_id);
    pthread_exit(NULL);
    return NULL;
}

void run_scans_by_techniques(ScanOptions *options) {
    int num_threads = options->speedup; // Nombre de threads demandé
    pthread_t threads[num_threads];
    ScanThreadData thread_data[num_threads];

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
    printf("scan_count %d portsTabSize %d num_threads %d combinations_per_thread %d extra_combinations %d\n", options->scan_count, options->portsTabSize, num_threads, combinations_per_thread, extra_combinations);

    int current_combination = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].options = options;

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
        if(thread_data[i].start_scan == thread_data[i].end_scan)
            thread_data[i].end_scan++;
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
        // printf("Thread %d joined.\n", i);
    }
    free(packet);
}



