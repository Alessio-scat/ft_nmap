#include "../../../include/ft_nmap.h"

/*
    strchr: Finds the first occurrence of a character in a string.
    sscanf: Parses formatted data from a string into variables.
*/

int validate_ports(const char *ports) {
    regex_t regex;
    int ret = regcomp(&regex, "^([0-9]+(-[0-9]+)?)(,[0-9]+(-[0-9]+)?)*$", REG_EXTENDED);
    if (ret) {
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
    while (token != NULL) {
        int start, end;
        // Check for leading zeros which are not allowed
        if (token[0] == '0' && strlen(token) > 1) {
            free(ports_copy);
            return 0;
        }
        if (strchr(token, '-') != NULL) { // Handle ranges like "5-15"
            sscanf(token, "%d-%d", &start, &end);
            // Check if values are within valid range and correctly ordered
            if (start < 1 || end > 1024 || start > end) {
                free(ports_copy);
                return 0;
            }
        } else { // Handle individual ports like "80"
            start = atoi(token);
            // Check if the port is within the valid range
            if (start < 1 || start > 1024) {
                free(ports_copy);
                return 0;
            }
        }
        token = strtok(NULL, ","); // continue the loop because strtok put \0 end 
    }
    free(ports_copy);
    return 1; // Ports are valid
}

// Handle the --ports option
void handle_ports_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        if (validate_ports(av[*i + 1])) {
            options->ports = av[*i + 1];
            (*i)++;
        } else {
            fprintf(stderr, "Error: Invalid port range or list: %s\n", av[*i + 1]); exit(1);
        }
    } else {
        fprintf(stderr, "Error: --ports option requires a port range or list.\n"); exit(1);
    }
}

