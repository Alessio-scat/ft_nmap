#include "ft_nmap.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// void *threaded_scan(void *arg) {
//     ScanThreadData *data = (ScanThreadData *)arg;
//     ScanOptions *options = data->options;

//     int sock; // Declare `sock` at the beginning of the function
//     sock = 1;
//     pthread_mutex_lock(&mutex);
//     char *packet = data->packet;
//     struct iphdr *iph = data->iph;
//     struct sockaddr_in dest = data->dest;

//     // Boucle sur les scans assignés
//     for (int scan = data->start_scan; scan < data->end_scan; scan++) {
//         // Synchronisation pour les modifications partagées
//         stop_pcap = false;
//         // options->currentScan = scan;
//         options->scan_type = options->tabscan[scan];
//         if (options->scan_type == 6) {
//             sock = create_udp_socket(); // Use UDP socket for type 6 scans
//             build_ip_header_udp(iph, &dest, options);
//         } else {
//             sock = create_raw_socket(); // Use raw socket for other scan types
//             build_ip_header(iph, &dest, options);
//         }
//         for (int j = data->start_port; j < data->end_port; j++) {
//             int target_port = options->portsTab[j];
//             // printf("%d %d\n",target_port, scan_type);
//             dest.sin_port = htons(target_port); // Définir le port cible
//             if (options->scan_type == UDP) {
//                 // Initialiser les en-têtes IP et UDP
//                 memset(packet, 0, 4096); // Nettoyer le buffer
//                 struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

//                 build_udp_header_udp(udph, target_port);

//                 // Envoyer le paquet
//                 if (sendto(sock, packet, htons(iph->tot_len), 0,
//                         (struct sockaddr *)&dest, sizeof(dest)) < 0) {
//                     perror("Failed to send UDP packet");
//                 }
//             } else {
//                 // Construire et envoyer les paquets TCP
//                 build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
//                 send_packet(sock, packet, iph, &dest);
//             }

//             // Petit délai entre les envois
//             usleep(1000);
//         }
        
//     }
//     pthread_mutex_unlock(&mutex);
//     // printf("Thread %d: Finished all scans.\n", data->thread_id);
//     pthread_exit(NULL);
//     return NULL;
// }

void build_tcp_header_thread(struct tcphdr *tcph, int target_port, int scan_type) {
    tcph->source = htons(20000 + scan_type);  // Port source aléatoire
    tcph->dest = htons(target_port);  // Port cible
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // Longueur de l'en-tête TCP
    if (scan_type == SYN){
        tcph->syn = 1;
    }
    else
        tcph->syn = 0;
    if (scan_type == FIN || scan_type == XMAS) {
        tcph->fin = 1; 
    }
    else
        tcph->fin = 0;   // Flag FIN désactivé
    tcph->rst = 0;   // Flag RST désactivé
    if (scan_type == XMAS){
        tcph->psh = 1;   
        tcph->urg = 1;   
    }
    else{
        tcph->psh = 0;   // Flag PSH désactivé
        tcph->urg = 0;   // Flag URG désactivé
    }
    if (scan_type == ACK) {
        tcph->ack = 1; 
    }
    else
        tcph->ack = 0;   // Flag ACK désactivé
    tcph->window = htons(5840);  // Taille de la fenêtre TCP
    tcph->check = 0;  // Le checksum sera calculé plus tard
    tcph->urg_ptr = 0;  // Pointeur urgent désactivé
}

void *threaded_scan(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;

    // Créez un buffer local par thread
    char *packet = malloc(4096);
    if (!packet) {
        perror("Memory allocation failed");
        pthread_exit(NULL);
    }
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest = data->dest;

    // Boucle sur les scans assignés
    for (int scan = data->start_scan; scan < data->end_scan; scan++) {
        int scan_type = data->options->tabscan[scan]; // Utiliser une copie locale

        int sock;
        if (scan_type == 6) {
            sock = create_udp_socket();
            build_ip_header_udp(iph, &dest, data->options);
        } else {
            sock = create_raw_socket();
            build_ip_header(iph, &dest, data->options);
        }

        for (int j = data->start_port; j < data->end_port; j++) {
            int target_port = data->options->portsTab[j];
            dest.sin_port = htons(target_port);

            if (scan_type == UDP) {
                memset(packet, 0, 4096);
                struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
                build_udp_header_udp(udph, target_port);
                if (sendto(sock, packet, htons(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                    perror("Failed to send UDP packet");
                }
            } else {
                build_tcp_header_thread((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, scan_type);
                send_packet(sock, packet, iph, &dest);
            }
            usleep(1000);
        }
        close(sock);
    }

    free(packet);
    pthread_exit(NULL);
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

    printf("scan_count %d portsTabSize %d num_threads %d combinations_per_thread %d extra_combinations %d\n", 
           options->scan_count, options->portsTabSize, num_threads, combinations_per_thread, extra_combinations);

    int current_combination = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].options = options;

        thread_data[i].packet = packet;
        thread_data[i].iph = iph;
        thread_data[i].dest = dest;

        // Calculer les combinaisons pour ce thread
        int start_combination = current_combination;
        int end_combination = start_combination + combinations_per_thread + (i < extra_combinations ? 1 : 0);

        // Si c'est le dernier thread, inclure toutes les combinaisons restantes
        if (i == num_threads - 1) {
            end_combination = total_combinations;
        }

        current_combination = end_combination;

        // Diviser les scans et les ports
        thread_data[i].start_scan = start_combination / options->portsTabSize;
        thread_data[i].end_scan = end_combination / options->portsTabSize;

        thread_data[i].start_port = start_combination % options->portsTabSize;
        thread_data[i].end_port = end_combination % options->portsTabSize;

        // Si le thread couvre plusieurs scans, ajuster les ports
        if (thread_data[i].start_scan != thread_data[i].end_scan) {
            thread_data[i].start_port = 0;               // Début des ports pour le premier scan
            thread_data[i].end_port = options->portsTabSize; // Fin des ports pour le dernier scan
        }

        // Si c'est le dernier thread et que les ports doivent s'étendre
        if (i == num_threads - 1) {
            thread_data[i].end_scan = options->scan_count;
            thread_data[i].end_port = options->portsTabSize;
        }
        if(thread_data[i].start_scan == thread_data[i].end_scan)
            thread_data[i].end_scan++;
        // Afficher les plages pour le thread
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
    }

    free(packet);
}