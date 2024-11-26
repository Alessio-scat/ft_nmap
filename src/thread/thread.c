#include "ft_nmap.h"

void *scan_technique_thread(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;

    // Définir la technique de scan pour ce thread
    data->options->scan_type = data->scan_type;
    data->options->currentScan = data->currentScan;
    printf("current %d\n", data->currentScan);
    printf("Thread %d exécutant le scan de type %d\n", data->thread_id, data->scan_type);
    if(data->scan_type == 6)
    {
       udp_scan_all_ports(data->options); 
    }
    else{
        printf("ici\n\n");
        // Envoyer les paquets pour ce type de scan
        send_all_packets(data->sock, data->packet, data->iph, &data->dest, data->options);

        // Capturer les réponses pour ce type de scan
        wait_for_responses(data->handle, data->options);
    }
    
    printf("Thread %d terminé\n", data->thread_id);
    pthread_exit(NULL);
}


void run_scans_by_techniques(ScanOptions *options) {
    int num_techniques = options->scan_count; // Nombre de techniques de scan
    pthread_t threads[num_techniques];
    ScanThreadData thread_data[num_techniques];

    int sock = create_raw_socket();
    int optval = 1;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    // Initialiser pcap une seule fois pour capturer les réponses
    pcap_t *handle = init_pcap(options->local_interface);

    // Créer un thread pour chaque technique
    for (int i = 0; i < num_techniques; i++) {
        // Assigner les informations nécessaires au thread
        thread_data[i].thread_id = i;
        thread_data[i].scan_type = options->tabscan[i]; // Type de scan
        thread_data[i].currentScan = i;                // Assignation unique
        thread_data[i].options = options;
        thread_data[i].sock = sock;
        thread_data[i].handle = handle;

        // Préparer le paquet pour ce thread
        memset(thread_data[i].packet, 0, sizeof(thread_data[i].packet));
        thread_data[i].iph = (struct iphdr *)thread_data[i].packet;
        thread_data[i].dest.sin_family = AF_INET;
        thread_data[i].dest.sin_addr.s_addr = inet_addr(options->ip_address);

        // Construire l'en-tête IP
        build_ip_header(thread_data[i].iph, &thread_data[i].dest, options);

        if(options->tabscan[i] == 6){
            if (pthread_create(&threads[i], NULL, scan_technique_thread, &thread_data[i]) != 0) {
            perror("Failed to create thread");
            exit(1);
        }
        }
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