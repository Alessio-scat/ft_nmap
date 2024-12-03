#include "../../../include/ft_nmap.h"

/*
    strchr: Finds the first occurrence of a character in a string.
    sscanf: Parses formatted data from a string into variables.
    strtok: divides a string into segments ("tokens") based on one or more delimiters.
*/

// Fonction pour vérifier si un port est déjà dans portsTab
int is_port_in_list(int *ports, int num_ports, int port) {
    for (int i = 0; i < num_ports; i++) {
        if (ports[i] == port) {
            return 1; // port already list
        }
    }
    return 0; // port not in the list
}

// Fonction pour valider, parser et stocker les ports
int validate_and_parse_ports(const char *ports, ScanOptions *options) {
    regex_t regex;
    int ret = regcomp(&regex, "^([0-9]+(-[0-9]+)?)(,[0-9]+(-[0-9]+)?)*$", REG_EXTENDED);
    if (ret) {
        cleanup_options(options);
        fprintf(stderr, "Error: Failed to compile regex for port validation.\n");
        return 0;
    }

    ret = regexec(&regex, ports, 0, NULL, 0);
    regfree(&regex);

    if (ret != 0)
        return 0;

    // Split and validate each port/range
    char *ports_copy = strdup(ports);
    char *token = strtok(ports_copy, ",");
    options->portsTabSize = 0;

    // Loop through each token to process individual ports or ranges
    while (token != NULL) {
        int start, end;

        // Vérifie pour les zéros en tête
        if (token[0] == '0' && strlen(token) > 1) {
            free(ports_copy);
            return 0;
        }

        // Handle ranges like "5-15"
        if (strchr(token, '-') != NULL) { 
            sscanf(token, "%d-%d", &start, &end);
            if (start < 1 || end > MAX_PORT || start > end) {
                free(ports_copy);
                return 0;
            }
            for (int i = start; i <= end; i++) {
                if (!is_port_in_list(options->portsTab, options->portsTabSize, i)) {
                    options->portsTab[options->portsTabSize++] = i;
                }
            }
        } else { // // Handle single ports like "80"
            start = atoi(token);
            if (start < 1 || start > MAX_PORT) {
                free(ports_copy);
                return 0;
            }
            // Add the port to portsTab if it's not already present
            if (!is_port_in_list(options->portsTab, options->portsTabSize, start)) {
                options->portsTab[options->portsTabSize++] = start;
            }
        }
        token = strtok(NULL, ",");
    }

    free(ports_copy);
    return 1; // Ports valides ok
}

int comp (const void * elem1, const void * elem2) 
{
    int f = *((int*)elem1);
    int s = *((int*)elem2);
    if (f > s) return  1;
    if (f < s) return -1;
    return 0;
}

// Handle the --ports option
void handle_ports_option(int *i, int ac, char **av, ScanOptions *options) {
    options->flag_ports = 1;
    if (*i + 1 < ac) {
        if (validate_and_parse_ports(av[*i + 1], options)) {
            options->ports = av[*i + 1];
            qsort(options->portsTab, options->portsTabSize, sizeof(int), comp);
            (*i)++;
        } else {
            cleanup_options(options);
            fprintf(stderr, "Error: Invalid port range or list: %s\n", av[*i + 1]);
            exit(1);
        }
    } else {
        cleanup_options(options);
        fprintf(stderr, "Error: --ports option requires a port range or list.\n");
        exit(1);
    }
}

