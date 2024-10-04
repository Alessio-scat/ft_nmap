#include "../include/ft_nmap.h"

int main(int ac, char **av)
{
    ScanOptions options = {NULL, NULL, 0, NULL, {0}, 0, NULL, NULL, 0, NULL, NULL};

    parse_arguments(ac, av, &options);
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
    

    for (int j = 0; j < options.ip_count; j++)
        free(options.ip_list[j]);
    free(options.ip_list);
    return 0;
}