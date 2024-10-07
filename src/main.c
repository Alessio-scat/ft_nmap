#include "../include/ft_nmap.h"

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

int main(int ac, char **av) {
    // Initialisation de ScanOptions
    ScanOptions options = {NULL, NULL, NULL, 0, NULL, {0}, 0, 0, NULL, NULL, 0, NULL, NULL, NULL};

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
    initialize_status(&options, 1, MAX_PORT);
    options.local_ip = get_local_ip();
    options.local_interface = get_local_interface();

    // Afficher la configuration de la commande
    printf("-----------COMMAND--------------\n");
    printf("IP Address: %s\n", options.ip_address);
    printf("Ports: %s\n", options.ports);
    printf("File: %s\n", options.file);
    for (int j = 0; j < options.ip_count; j++)
        printf("   Stored IP: %s\n", options.ip_list[j]);
    printf("Speedup: %d\n", options.speedup);
    printf("Scan Type: %s\n", options.scan_type);
    printf("--------------------------------\n");

    // Effectuer le scan
    print_starting_message();
    syn_scan_all_ports(&options);

    // Afficher les ports, en excluant ceux dans l'état "CLOSED"
    print_ports_excluding_state(&options, "CLOSED");

    // Libérer la mémoire
    for (int j = 0; j < options.ip_count; j++)
        free(options.ip_list[j]);
    free(options.ip_list);
    for (int i = 0; i < 1; i++) {
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
    printf("\nNmap done: 1 IP address (1 host up) scanned in %.2f seconds\n", elapsed_time);

    return 0;
}