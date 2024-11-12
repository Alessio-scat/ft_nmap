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

void print_ports_excluding_state(ScanOptions *options, char *excluded_state) {
    printf("Nmap scan report for %s (%s)\n", options->ip_host, options->ip_address);
    int total_ports = options->portsTabSize;

    // Boucle sur chaque technique de scan dans l'ordre
    for (int technique = 0; technique < options->scan_count; technique++) {
        int scan_type = options->tabscan[technique];
        const char *scan_name = get_scan_name(scan_type);
        if(options->tabscan[technique] == ACK)
            excluded_state = "UNFILTERED";
        else
            excluded_state = "CLOSED";
        int excluded_count = 0;

        // Comptage des ports dans l'état spécifié (par exemple, "CLOSED")
        for (int i = 0; i < options->portsTabSize; i++) {
            if (strcmp(options->status[technique][i], excluded_state) == 0) {
                excluded_count++;
            }
        }
        printf("\nScan type: %s\n", scan_name);
        if(excluded_count > 0)
            printf("Not shown: %d ports %s\n", excluded_count, excluded_state);
        
        if (total_ports > 25) {
            const char *first_state = options->status[technique][0];
            int all_ports_identical = 1;

            for (int i = 0; i < total_ports; i++) {
                if (strcmp(options->status[technique][i], first_state) != 0) {
                    all_ports_identical = 0;
                    break;
                }
            }
            if (all_ports_identical) {
                printf("All %d scanned ports are %s\n", total_ports, first_state);
                continue;
            }
        }
        printf("PORT    SERVICE         STATE\n");
        // Afficher les ports pour ce type de scan
        for (int i = 0; i < options->portsTabSize; i++) {
            if (strcmp(options->status[technique][i], excluded_state) != 0 || (options->flag_ports == 1 && total_ports < 26)) {
                const char *service_name = get_service_name(options->portsTab[i]);
                printf("%d/tcp    %-15s  %s\n", options->portsTab[i], service_name, options->status[technique][options->portsTab[i] - 1]);
            }
        }
    }
}
