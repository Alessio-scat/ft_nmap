#include "ft_nmap.h"

void *threaded_scan(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;
    ScanOptions *options = data->options;

    // Crée un socket local
    int sock = create_raw_socket();
    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
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
    // Boucles sur les scans et ports assignés
    // printf("start scan %d, end scan %d, start port %d, end port %d current scan %d, type scan %d\n",data->start_scan, data->end_scan, data->start_port, data->end_port, options->currentScan, options->scan_type);
    for (int scan = data->start_scan; scan < data->end_scan; scan++) {
        options->currentScan = scan;
        options->scan_type = options->tabscan[scan];
        printf("start scan %d, end scan %d, start port %d, end port %d current scan %d, type scan %d\n",data->start_scan, data->end_scan, data->start_port, data->end_port, options->currentScan, options->scan_type);
        for (int port_idx = data->start_port; port_idx < data->end_port; port_idx++) {

            int target_port = options->portsTab[port_idx];
            // printf("%d\n", target_port);
            dest.sin_port = htons(target_port);

            // Construire et envoyer le paquet
            build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
            send_packet(sock, packet, iph, &dest);
            usleep(1000);
        }
        wait_for_responses(handle, options);
    }

    close(sock);

    printf("Thread %d a terminé de scanner les ports %d à %d pour les techniques %d à %d.\n",
           data->thread_id, data->start_port, data->end_port, data->start_scan, data->end_scan);
    pcap_close(handle);
    pthread_exit(NULL);
    return NULL;
}


void run_scans_by_techniques(ScanOptions *options) {
    int num_threads = options->speedup;
    pthread_t threads[num_threads];
    ScanThreadData thread_data[num_threads];

    // Répartition des ports
    int ports_per_thread = options->portsTabSize / num_threads;
    int extra_ports = options->portsTabSize % num_threads;

    // Si un seul scan, tous les threads partagent le même scan
    int start_scan = 0;
    int end_scan = options->scan_count; // Cela sera 1 si scan_count == 1

    int current_port = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].options = options;

        // Répartition des ports
        thread_data[i].start_port = current_port;
        thread_data[i].end_port = current_port + ports_per_thread + (i < extra_ports ? 1 : 0);
        current_port = thread_data[i].end_port;

        // Tous les threads partagent la même plage de scans si scan_count == 1
        thread_data[i].start_scan = start_scan;
        thread_data[i].end_scan = end_scan;

        // Affiche les plages pour débogage
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
}