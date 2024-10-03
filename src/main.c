#include "../include/ft_nmap.h"

int main(int ac, char **av)
{
    ScanOptions options = {NULL, NULL, 0, NULL, {0}, 0, NULL, NULL, 0};

    parse_arguments(ac, av, &options);

    printf("-----------COMMAND--------------\n");
    printf("IP Address: %s\n", options.ip_address);
    printf("Ports: %s\n", options.ports);
    printf("File: %s\n", options.file);
    for (int j = 0; j < options.ip_count; j++)
        printf("   Stored IP: %s\n", options.ip_list[j]);
    printf("Speedup: %d\n", options.speedup);
    printf("Scan Type: %s\n", options.scan_type);
    printf("--------------------------------\n");

    printf("Ports stockés sans doublons :\n");
    for (int j = 0; j < options.portsTabSize; j++) {
        printf("Port: %d\n", options.portsTab[j]);
    }

    for (int j = 0; j < options.ip_count; j++)
        free(options.ip_list[j]);
    free(options.ip_list);
    int i = syn_scan(options.ip_address, options.portsTab[0]);
    (void)i;
    return 0;
}