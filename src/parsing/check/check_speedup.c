#include "../../../include/ft_nmap.h"

int validate_speedup(int speedup) {
    return speedup >= 0 && speedup <= 250;
}

int is_valid_number(char *str) {
    if (str == NULL || *str == '\0')
        return 0;

    for (int i = 0; str[i] != '\0'; i++)
        if (!isdigit((unsigned char)str[i]))
            return 0;
    return 1;
}

// Handle the --speedup option
void handle_speedup_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        if (is_valid_number(av[*i + 1])) {
            options->speedup = atoi(av[*i + 1]);
            if (!validate_speedup(options->speedup)){
                cleanup_options(options);
                fprintf(stderr, "Error: --speedup must be between 0 and 250.\n");
                exit(1);
            }
        } else {
            cleanup_options(options);
            fprintf(stderr, "Error: --speedup requires a valid number.\n");
            exit(1);
        }
        (*i)++;
    } else {
        cleanup_options(options);
        fprintf(stderr, "Error: --speedup option requires a number.\n");
        exit(1);
    }
}