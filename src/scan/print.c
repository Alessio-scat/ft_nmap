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

void print_os_detection(ScanOptions *options){
    if(options->OS == 1){
        if(options->ttl == 0){
            printf("No exact OS matches for host\n");
        } else if (options->ttl <= 64) {
            printf("OS details: Linux ou Unix\n");
        } else if (options->ttl <= 128) {
            printf("OS details: Windows\n");
        }
        else
            printf("No exact OS matches for host\n");
    }
}

void print_ports_excluding_state(ScanOptions *options, char *excluded_state) {
    printf("Nmap scan report for %s (%s)\n", options->ip_host, options->ip_address);
    int total_ports = options->portsTabSize;
    print_os_detection(options);
    // Boucle sur chaque technique de scan dans l'ordre
    for (int technique = 0; technique < options->scan_count; technique++) {
        int scan_type = options->tabscan[technique];
        const char *scan_name = get_scan_name(scan_type);
        if(options->tabscan[technique] == ACK)
            excluded_state = "UNFILTERED";
        else if(options->tabscan[technique] == UDP)
            excluded_state = "open|filtered";
        else
            excluded_state = "CLOSED";
        int excluded_count = 0;
        int filtered_count = 0;

        // Comptage des ports dans l'état spécifié (par exemple, "CLOSED")
        for (int i = 0; i < options->portsTabSize; i++) {
            if (strcmp(options->status[technique][i], excluded_state) == 0) {
                excluded_count++;
            }
            if (strcmp(options->status[technique][i], "FILTERED") == 0) {
                filtered_count++;
            }
        }
        printf("\nScan type: %s\n", scan_name);
        if(excluded_count > 0)
            printf("Not shown: %d ports %s\n", excluded_count, excluded_state);
        if(filtered_count > 10)
            printf("Not shown: %d ports FILTERED\n", filtered_count);
        
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

        // Parcourir les ports définis dans portsTab
        for (int i = 0; i < options->portsTabSize; i++) {
            int port = options->portsTab[i];
            const char *port_status = options->status[technique][port - 1]; // Statut du port (via index)

            // Vérifier si le port doit être affiché
            if (strcmp(port_status, excluded_state) != 0 || (options->flag_ports == 1 && total_ports < 26)){
                if(filtered_count < 10 || strcmp(port_status, "FILTERED") != 0){
                    const char *service_name = get_service_name(port);

                    // Afficher les informations du port
                    if (scan_type == 6) { // UDP
                        printf("%d/udp    %-15s  %s\n", port, service_name, port_status);
                    } else { // TCP
                        printf("%d/tcp    %-15s  %s\n", port, service_name, port_status);
                    }
                }
            }
        }
        printf("filtered %d\n", filtered_count);
    }
}
