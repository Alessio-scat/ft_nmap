#include "../include/ft_nmap.h"

int main(int ac, char **av)
{
    ScanOptions options = {NULL, NULL, NULL, 0, NULL};

    parse_arguments(ac, av, &options);

    printf("IP Address: %s\n", options.ip_address);
    printf("Ports: %s\n", options.ports);
    printf("File: %s\n", options.file);
    printf("Speedup: %d\n", options.speedup);
    printf("Scan Type: %s\n", options.scan_type);
    return 0;
}