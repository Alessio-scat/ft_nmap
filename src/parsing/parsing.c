#include "../include/ft_nmap.h"

void handle_ip_option(int *i, int ac, char **av, ScanOptions *options);
void handle_ports_option(int *i, int ac, char **av, ScanOptions *options);
void handle_file_option(int *i, int ac, char **av, ScanOptions *options);
void handle_speedup_option(int *i, int ac, char **av, ScanOptions *options);
void handle_scan_option(int *i, int ac, char **av, ScanOptions *options);
int validate_ip_or_hostname(const char *input);
int validate_ports(const char *ports);
int validate_file(const char *filename);
int validate_speedup(int speedup);
int validate_scan_type(const char *scan_type);

void print_help() {
    printf("Usage: ft_nmap [OPTIONS]\n");
    printf("--help                   Print this help screen\n");
    printf("--ports [NUMBER/RANGE]   Specify ports to scan (e.g., 1-1024 or 1,2,3 or 1,5-15)\n");
    printf("--ip [IP_ADDRESS]        Specify the IP address to scan in dot format\n");
    printf("--file [FILE]            File name containing IP addresses to scan\n");
    printf("--speedup [NUMBER]       Number of parallel threads to use (max 250)\n");
    printf("--scan [TYPE]            Type of scan to perform (SYN/NULL/FIN/XMAS/ACK/UDP)\n");
}

void parse_arguments(int ac, char **av, ScanOptions *options) {
    for (int i = 1; i < ac; i++) {
        if (strcmp(av[i], "--help") == 0) {
            print_help(); exit(0);
        } else if (strcmp(av[i], "--ip") == 0) {
            handle_ip_option(&i, ac, av, options);
        } else if (strcmp(av[i], "--ports") == 0) {
            handle_ports_option(&i, ac, av, options);
        } else if (strcmp(av[i], "--file") == 0) {
            handle_file_option(&i, ac, av, options);
        } else if (strcmp(av[i], "--speedup") == 0) {
            handle_speedup_option(&i, ac, av, options);
        } else if (strcmp(av[i], "--scan") == 0) {
            handle_scan_option(&i, ac, av, options);
        } else {
            fprintf(stderr, "Unknown argument: %s\n", av[i]); print_help(); exit(1);
        }
    }

    // Minimal validation to ensure either IP or file is specified
    if (options->ip_address == NULL && options->file == NULL) {
        fprintf(stderr, "Error: You must specify an IP address with --ip or a file with --file.\n"); exit(1);
    }
}