#include "../../../include/ft_nmap.h"

int validate_scan_type(char *scan_type) {
    const char *valid_scans[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP"};
    for (int i = 0; i < 6; i++) {
        if (strcmp(scan_type, valid_scans[i]) == 0)
            return 1; // Valid scan type
    }
    return 0; // Invalid scan type
}

// Handle the --scan option
void handle_scan_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        if (validate_scan_type(av[*i + 1])) {
            options->scan_type = av[*i + 1];
            (*i)++;
        } else {
            fprintf(stderr, "Error: Invalid scan type: %s\n", av[*i + 1]); exit(1);
        }
    } else {
        fprintf(stderr, "Error: --scan option requires a scan type.\n"); exit(1);
    }
}