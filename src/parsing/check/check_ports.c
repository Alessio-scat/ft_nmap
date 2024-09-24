#include "../../../include/ft_nmap.h"

/*
    strchr: Finds the first occurrence of a character in a string.
    sscanf: Parses formatted data from a string into variables.
*/

// Fonction pour vérifier si un port est déjà dans portsTab
int is_port_in_list(int *ports, int num_ports, int port) {
    for (int i = 0; i < num_ports; i++) {
        if (ports[i] == port) {
            return 1; // Le port est déjà dans la liste
        }
    }
    return 0; // Le port n'est pas dans la liste
}

// Fonction pour valider, parser et stocker les ports
int validate_and_parse_ports(const char *ports, ScanOptions *options) {
    regex_t regex;
    int ret = regcomp(&regex, "^([0-9]+(-[0-9]+)?)(,[0-9]+(-[0-9]+)?)*$", REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "Error: Failed to compile regex for port validation.\n");
        return 0;
    }

    ret = regexec(&regex, ports, 0, NULL, 0);
    regfree(&regex);

    if (ret != 0) {
        return 0; // Format des ports non valide
    }

    // Split and validate each port/range
    char *ports_copy = strdup(ports);
    char *token = strtok(ports_copy, ",");
    options->portsTabSize = 0; // Réinitialise la taille des ports

    while (token != NULL) {
        int start, end;

        // Vérifie pour les zéros en tête
        if (token[0] == '0' && strlen(token) > 1) {
            free(ports_copy);
            return 0;
        }

        if (strchr(token, '-') != NULL) { // Gérer les plages comme "5-15"
            sscanf(token, "%d-%d", &start, &end);
            if (start < 1 || end > 1024 || start > end) {
                free(ports_copy);
                return 0;
            }
            for (int i = start; i <= end; i++) {
                if (!is_port_in_list(options->portsTab, options->portsTabSize, i)) {
                    options->portsTab[options->portsTabSize++] = i;
                }
            }
        } else { // Gérer les ports individuels comme "80"
            start = atoi(token);
            if (start < 1 || start > 1024) {
                free(ports_copy);
                return 0;
            }
            if (!is_port_in_list(options->portsTab, options->portsTabSize, start)) {
                options->portsTab[options->portsTabSize++] = start;
            }
        }
        token = strtok(NULL, ",");
    }

    free(ports_copy);
    return 1; // Ports valides et stockés dans portsTab
}

// Handle the --ports option
void handle_ports_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        if (validate_and_parse_ports(av[*i + 1], options)) {
            options->ports = av[*i + 1];
            (*i)++;
        } else {
            fprintf(stderr, "Error: Invalid port range or list: %s\n", av[*i + 1]);
            exit(1);
        }
    } else {
        fprintf(stderr, "Error: --ports option requires a port range or list.\n");
        exit(1);
    }
}
