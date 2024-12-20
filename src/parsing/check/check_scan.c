#include "../../../include/ft_nmap.h"

int validate_scan_type(char *scan_type) {
    if (strcmp(scan_type, "SYN") == 0) return SYN;
    if (strcmp(scan_type, "NULL") == 0) return SCAN_NULL; 
    if (strcmp(scan_type, "FIN") == 0) return FIN;
    if (strcmp(scan_type, "XMAS") == 0) return XMAS;
    if (strcmp(scan_type, "ACK") == 0) return ACK;
    if (strcmp(scan_type, "UDP") == 0) return UDP;
    return 0; // Invalid scan type
}

void handle_scan_option(int *i, int ac, char **av, ScanOptions *options) {
    int scan_count = 0;

    while (*i + 1 < ac && scan_count < MAX_SCANS) {
        // check if arg start "--"
        if (strncmp(av[*i + 1], "--", 2) == 0)
            break;

        int scan_code = validate_scan_type(av[*i + 1]);
        if (scan_code) {

            // check if the scan is already in tabscan
            bool already_exists = false;
            for (int j = 0; j < scan_count; j++) {
                if (options->tabscan[j] == scan_code) {
                    already_exists = true;
                    break;
                }
            }

            if (already_exists) {
                cleanup_options(options);
                fprintf(stderr, "Error: Duplicate scan type: %s\n", av[*i + 1]);
                print_help();
                exit(1);
            }

            options->tabscan[scan_count++] = scan_code;
            (*i)++;
        } 
        else {
            cleanup_options(options);
            fprintf(stderr, "Error: Invalid scan type: %s\n", av[*i + 1]);
            print_help();
            exit(1);
        }
    }

    if (scan_count == 0) {
        cleanup_options(options);
        fprintf(stderr, "Error: --scan option requires at least one valid scan type.\n");
        exit(1);
    }

    options->scan_count = scan_count;  // Store the number of scans parsed
}
