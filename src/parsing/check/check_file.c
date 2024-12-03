#include "../../../include/ft_nmap.h"

int validate_ip_or_hostname(char *input);

int validate_file(char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1; // File is accessible
    }
    return 0; // File cannot be read
}

void trim_whitespace(char *str) {
    char *end;

    char *start = str;
    while (isspace((unsigned char)*start)) {
        start++;
    }
    memmove(str, start, strlen(start) + 1);
    if (*str == '\0') return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';
}


void parse_file(char *filename, ScanOptions *options) {
    FILE *file = fopen(filename, "r");
    if (file == NULL){
        cleanup_options(options);
        fprintf(stderr, "Error: Cannot open file: %s\n", filename);
        exit(1);
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        trim_whitespace(line);
        if (strlen(line) == 0)
            continue; // skip lign empty

        if (!validate_ip_or_hostname(line)) {
            cleanup_options(options);
            fprintf(stderr, "Error: Invalid IP address or hostname found in file: %s\n", line);
            fclose(file);
            exit(1);
        }

        options->ip_list = realloc(options->ip_list, (options->ip_count + 1) * sizeof(char *));
        if (options->ip_list == NULL) {
            cleanup_options(options);
            fprintf(stderr, "Error: Memory allocation failed.\n");
            fclose(file);
            exit(1);
        }

        options->ip_list[options->ip_count] = strdup(line);
        if (options->ip_list[options->ip_count] == NULL) {
            cleanup_options(options);
            fprintf(stderr, "Error: Memory allocation failed for IP.\n");
            fclose(file);
            exit(1);
        }

        options->ip_count++;
    }

    fclose(file);
}

// Handle the --file option
void handle_file_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        if (validate_file(av[*i + 1])) {
            options->file = av[*i + 1];
            parse_file(options->file, options);
            (*i)++;
        } else {
            cleanup_options(options);
            fprintf(stderr, "Error: Invalid file or file cannot be read: %s\n", av[*i + 1]); exit(1);
        }
    } else {
        cleanup_options(options);
        fprintf(stderr, "Error: --file option requires a filename.\n"); exit(1);
    }
}