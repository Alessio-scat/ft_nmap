#include "../include/ft_nmap.h"

ScanOptions *global_options = NULL;

void print_starting_message() {
    time_t now;
    struct tm *local_time;
    char time_str[100];
    
    // Récupérer l'heure actuelle
    time(&now);
    
    // Convertir en heure locale
    local_time = localtime(&now);
    
    // Formater la date et l'heure (2024-10-07 17:42 CEST)
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M %Z", local_time);

    // Afficher le message de démarrage
    printf("Starting ft_nmap at %s\n", time_str);
}

const char* get_scan_name(int scan_code) {
    switch (scan_code) {
        case SYN: return "SYN";
        case SCAN_NULL: return "NULL";
        case FIN: return "FIN";
        case XMAS: return "XMAS";
        case ACK: return "ACK";
        case UDP: return "UDP";
        default: return "UNKNOWN"; // Pour gérer des cas non définis
    }
}

void print_scan_types(ScanOptions *options) {
    printf("Selected scan types: ");
    for (int i = 0; i < options->scan_count; i++) {
        printf("%s", get_scan_name(options->tabscan[i]));
        if (i < options->scan_count - 1) {
            printf(", "); // Ajouter une virgule entre les types de scan
        }
    }
    printf("\n");
}


void signal_handler(int signum) {
    if (signum == SIGINT) {
        printf("\nSignal SIGINT reçu (Ctrl+C). Libération des ressources...\n");

        if (global_options != NULL) {
            // Libérer les ressources allouées dynamiquement
            if (global_options->local_interface)
                free(global_options->local_interface);
            if (global_options->local_ip)
                free(global_options->local_ip);
            if (global_options->ip_host)
                free(global_options->ip_host);
            if (global_options->ip_address)
                free(global_options->ip_address);

            for (int j = 0; j < global_options->ip_count; j++)
                free(global_options->ip_list[j]);
            free(global_options->ip_list);
            for (int i = 0; i < global_options->scan_count; i++) {
                for (int j = 0; j < MAX_PORT; j++) {
                    if (global_options->status[i][j] != NULL) {
                        free(global_options->status[i][j]);
                    }
                }
                free(global_options->status[i]);
            }
            free(global_options->status);

            printf("Libération des ressources terminée.\n");
        }

        if (global_handle) {
            pcap_breakloop(global_handle);
            pcap_close(global_handle);
            global_handle = NULL;
        }

        printf("Arrêt du programme.\n");
        exit(0);
    }
}


int main(int ac, char **av) {
    // Initialisation de ScanOptions
    ScanOptions options = {NULL, NULL, NULL, 0, 0, {0}, 0, 0, NULL, NULL, 0, NULL, NULL, NULL, 0, {0}, 0, 0, 0};

    global_options = &options;
    signal(SIGINT, signal_handler);

    // Capturer le temps de début
    struct timeval start, end;
    gettimeofday(&start, NULL);  // Temps de début

    // Parsing des arguments et configuration
    parse_arguments(ac, av, &options);
    if (options.flag_ports == 0) {
        // Remplir options->portsTab avec les valeurs de 1 à 1024
        for (int port = 1; port <= 1024; port++) {
            options.portsTab[port - 1] = port;
        }
        // Mettre à jour la taille du tableau
        options.portsTabSize = 1024;
    }
    initialize_status(&options, options.scan_count, MAX_PORT);
    int use_loopback = strcmp(options.ip_address, "127.0.0.1") == 0;
    options.local_ip = get_local_ip(use_loopback);
    options.local_interface = get_local_interface(use_loopback);
    // Afficher la configuration de la commande
    printf("-----------COMMAND--------------\n");
    printf("IP Address: %s\n", options.ip_address);
    printf("IP locale: %s\n", options.local_ip);
    printf("IP locale: %s\n", options.local_interface);
    printf("Ports: %s\n", options.ports);
    printf("File: %s\n", options.file);
    for (int j = 0; j < options.ip_count; j++)
        printf("   Stored IP: %s\n", options.ip_list[j]);
    printf("Speedup: %d\n", options.speedup);
    print_scan_types(&options);
    printf("--------------------------------\n");

    // Effectuer le scan
    print_starting_message();
    tcp_scan_all_ports(&options);

    // Afficher les ports, en excluant ceux dans l'état "CLOSED"
    print_ports_excluding_state(&options, "CLOSED");

    if (options.local_interface)
        free(options.local_interface);
    if (options.local_ip)
        free(options.local_ip);
    if (options.ip_host)
        free(options.ip_host);
    if (options.ip_address)
        free(options.ip_address);

    // Libérer la mémoire
    for (int j = 0; j < options.ip_count; j++)
        free(options.ip_list[j]);
    free(options.ip_list);
    for (int i = 0; i < options.scan_count; i++) {
        for (int j = 0; j < MAX_PORT; j++) {
            if (options.status[i][j] != NULL) {
                free(options.status[i][j]);
            }
        }
        free(options.status[i]);
    }
    free(options.status);

    
    // Capturer le temps de fin
    gettimeofday(&end, NULL);  // Temps de fin

    // Calculer le temps écoulé (en secondes et microsecondes)
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

    // Afficher le temps écoulé
    printf("\nNmap done: %d IP address (1 host up) scanned in %.2f seconds\n", options.ip_count+1, elapsed_time);

    return 0;
}