#include "../../../include/ft_nmap.h"

int validate_speedup(int speedup) {
    return speedup >= 0 && speedup <= 250;
}

// Handle the --speedup option
void handle_speedup_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        options->speedup = atoi(av[*i + 1]);
        if (!validate_speedup(options->speedup)) {
            fprintf(stderr, "Error: --speedup must be between 0 and 250.\n"); exit(1);
        }
        (*i)++;
    } else {
        fprintf(stderr, "Error: --speedup option requires a number.\n"); exit(1);
    }
}