#include "../../../include/ft_nmap.h"

int validate_file(char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1; // File is accessible
    }
    return 0; // File cannot be read
}

// Handle the --file option
void handle_file_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        if (validate_file(av[*i + 1])) {
            options->file = av[*i + 1];
            (*i)++;
        } else {
            fprintf(stderr, "Error: Invalid file or file cannot be read: %s\n", av[*i + 1]); exit(1);
        }
    } else {
        fprintf(stderr, "Error: --file option requires a filename.\n"); exit(1);
    }
}