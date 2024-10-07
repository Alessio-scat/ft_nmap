#include "../include/ft_nmap.h"

int main(int ac, char **av)
{
    ScanOptions options = {NULL, NULL, NULL, 0, NULL, {0}, 0, 0, NULL, NULL, 0, NULL, NULL, NULL};

    parse_arguments(ac, av, &options);
    if (options.flag_ports == 0)
    {
        // Remplir options->portsTab avec les valeurs de 1 à 1024
        for (int port = 1; port <= 1024; port++)
        {
            options.portsTab[port - 1] = port;
        }
        // Mettre à jour la taille du tableau
        options.portsTabSize = 1024;
    }
    initialize_status(&options, 1, MAX_PORT);
    options.local_ip = get_local_ip();
    options.local_interface = get_local_interface();
    printf("-----------COMMAND--------------\n");
    printf("IP Address: %s\n", options.ip_address);
    printf("Ports: %s\n", options.ports);
    printf("File: %s\n", options.file);
    for (int j = 0; j < options.ip_count; j++)
        printf("   Stored IP: %s\n", options.ip_list[j]);
    printf("Speedup: %d\n", options.speedup);
    printf("Scan Type: %s\n", options.scan_type);
    printf("--------------------------------\n");

    syn_scan_all_ports(&options);
    print_ports_excluding_state(&options, "CLOSED");

    for (int j = 0; j < options.ip_count; j++)
        free(options.ip_list[j]);
    free(options.ip_list);
    for (int i = 0; i < 1; i++)
    {
        for (int j = 0; j < MAX_PORT; j++)
        {
            if (options.status[i][j] != NULL)
            {
                free(options.status[i][j]);
            }
        }
        free(options.status[i]);
    }
    free(options.status);


    return 0;
}