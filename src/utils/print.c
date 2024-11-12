#include "ft_nmap.h"
#include "ft_nmap_services.h"


const char *get_service_name(int port) {
    int num_services = sizeof(services_tcp) / sizeof(services_tcp[0]);
    for (int i = 0; i < num_services; i++) {
        if (services_tcp[i].port == port) {
            return services_tcp[i].name;
        }
    }
    return "unknown";  // Si le port n'est pas dans la liste
}

void print_ports_excluding_state(ScanOptions *options, const char *excluded_state) {
    printf("Nmap scan report for %s (%s)\n", options->ip_host, options->ip_address);
    int excluded_count = 0;

    // Comptage des ports dans l'état spécifié (par exemple, "CLOSED")
    for (int i = 0; i < options->portsTabSize; i++) {
        for (int technique = 0; technique < 1; technique++) {  // Si tu as plusieurs techniques, il faut boucler dessus
            if (strcmp(options->status[technique][i], excluded_state) == 0) {
                excluded_count++;
            }
        }
    }

    // Affichage du nombre de ports dans l'état exclu
    printf("Not shown: %d closed ports %s\n", excluded_count, excluded_state);

    // Affichage des détails des ports qui ne sont pas dans cet état exclu
    printf("PORT    SERVICE         STATE\n");
    for (int i = 0; i < options->portsTabSize; i++) {
        for (int technique = 0; technique < 1; technique++) {
            if (strcmp(options->status[technique][options->portsTab[i] - 1], excluded_state) != 0 || options->flag_ports == 1) {  // On affiche les ports qui ne sont pas dans l'état exclu
                
                // Utiliser la nouvelle fonction pour obtenir le nom du service
                const char *service_name = get_service_name(options->portsTab[i]);

                // Afficher les détails du port
                printf("%d/tcp    %-15s  %s\n", options->portsTab[i], service_name, options->status[technique][options->portsTab[i] - 1]);
            }
        }
    }
}