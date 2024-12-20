#include "../../../include/ft_nmap.h"

// Valide Ip or domain
int validate_ip_or_hostname(char *input) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, input, &(sa.sin_addr)) == 1)
        return 1; // Adresse IP valide

    const char *regex_pattern = "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
    regex_t regex;
    int ret = regcomp(&regex, regex_pattern, REG_EXTENDED);

    if (ret)
        exit(EXIT_FAILURE);

    ret = regexec(&regex, input, 0, NULL, 0);
    regfree(&regex);
    
    return ret == 0 ? 1 : 0;
}

char *resolve_hostname_to_ip(const char *hostname, ScanOptions *options) {
    (void)options;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    char *ip_address = NULL;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  // IPv4 

    if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
        ipv4 = (struct sockaddr_in *)res->ai_addr;
        ip_address = strdup(inet_ntoa(ipv4->sin_addr));
        freeaddrinfo(res);
    } else {
        return NULL;
    }
    
    return ip_address;
}

void handle_ip_option(int *i, int ac, char **av, ScanOptions *options) {

    while (*i + 1 < ac && strncmp(av[*i + 1], "--", 2) != 0) {
        char *input = av[*i + 1];

        // Add IP or domain name to list ip 
        options->ip_list = realloc(options->ip_list, (options->ip_count + 1) * sizeof(char *));
        if (options->ip_list == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for ip_list.\n");
            exit(1);
        }
        options->ip_list[options->ip_count] = strdup(input);
        if (options->ip_list[options->ip_count] == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for IP string.\n");
            exit(1);
        }
        options->ip_count++;
        (*i)++;
    }

    // Check if no IP has been added
    if (options->ip_count == 0) {
        fprintf(stderr, "Error: --ip option requires at least one IP address or hostname.\n");
        exit(1);
    }
}


void handle_ip_option_in_file(int *ip_index, ScanOptions *options) {
    while (*ip_index >= 0 && *ip_index < options->ip_count) {
        char *selected_ip = options->ip_list[*ip_index];

        // Libérer l'ancienne mémoire allouée à ip_host
        if (options->ip_host) {
            free(options->ip_host);
            options->ip_host = NULL;
        }
        // Libérer l'ancienne mémoire allouée à ip_address
        if (options->ip_address) {
            free(options->ip_address);
            options->ip_address = NULL;
        }

        // Stocker l'IP ou le nom d'hôte
        options->ip_host = strdup(selected_ip);
        if (!options->ip_host) {
            fprintf(stderr, "Error: Memory allocation failed for ip_host.\n");
            exit(1);
        }

        // Vérifie si l'entrée est une adresse IP valide
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, selected_ip, &(sa.sin_addr)) == 1) {
            // Si c'est une IP valide
            options->ip_address = strdup(selected_ip);
        } else {
            // Résolution du nom de domaine
            options->ip_address = resolve_hostname_to_ip(selected_ip, options);
        }

        if (options->ip_address == NULL) {
            fprintf(stderr, "Error: Unable to resolve IP address for %s. Skipping.\n\n", selected_ip);
            (*ip_index)++; // Passe à l'adresse suivante
            continue; // Essaie la prochaine adresse
        }
        break; // Quitte la boucle après une résolution réussie
    }

    if (*ip_index >= options->ip_count) {
        cleanup_options(options);
        fprintf(stderr, "Error: No valid IP addresses found.\n");
        exit(1);
    }
}


