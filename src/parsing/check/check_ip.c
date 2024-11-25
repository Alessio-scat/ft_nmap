#include "../../../include/ft_nmap.h"

// Valider si c'est une IP ou un nom de domaine
int validate_ip_or_hostname(char *input) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, input, &(sa.sin_addr)) == 1)
        return 1; // Adresse IP valide

    // Expression régulière pour valider un nom de domaine
    const char *regex_pattern = "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
    regex_t regex;
    int ret = regcomp(&regex, regex_pattern, REG_EXTENDED);

    if (ret)
        exit(EXIT_FAILURE);

    ret = regexec(&regex, input, 0, NULL, 0);
    regfree(&regex);
    
    return ret == 0 ? 1 : 0;
}

// Résoudre un nom de domaine en adresse IP
char *resolve_hostname_to_ip(const char *hostname) {
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    char *ip_address = NULL;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  // IPv4 uniquement

    if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
        ipv4 = (struct sockaddr_in *)res->ai_addr;
        ip_address = strdup(inet_ntoa(ipv4->sin_addr));
        freeaddrinfo(res);  // Libérer la mémoire allouée par getaddrinfo
    } else {
        fprintf(stderr, "Error: Unable to resolve hostname: %s\n", hostname);
        exit(1);
    }
    
    return ip_address;
}

// Gérer l'option --ip
void handle_ip_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        char *input = av[*i + 1];
        options->ip_host = strdup(input); // Stocke l'IP ou le nom d'hôte

        // Vérifie si l'entrée est une adresse IP valide
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, input, &(sa.sin_addr)) == 1) {
            // Si c'est une IP valide, l'utiliser directement
            options->ip_address = strdup(input);
        } else {
            // Sinon, essayer de résoudre le nom de domaine
            options->ip_address = resolve_hostname_to_ip(input);
        }

        if (options->ip_address == NULL) {
            fprintf(stderr, "Error: Unable to resolve IP address for %s\n", input);
            exit(1);
        }
        (*i)++;
    } else {
        fprintf(stderr, "Error: --ip option requires an IP address or hostname.\n");
        exit(1);
    }
}

void handle_ip_option_in_file(int ip_index, ScanOptions *options) {
    if (ip_index >= 0 && ip_index < options->ip_count) {
        // Récupère l'IP à partir du tableau ip_list en fonction de ip_index
        char *selected_ip = options->ip_list[ip_index];
        options->ip_host = strdup(selected_ip); // Stocke l'IP ou le nom d'hôte

        // Vérifie si l'entrée est une adresse IP valide
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, selected_ip, &(sa.sin_addr)) == 1) {
            // Si c'est une IP valide, l'utiliser directement
            options->ip_address = strdup(selected_ip);
        } else {
            // Sinon, essayer de résoudre le nom de domaine
            options->ip_address = resolve_hostname_to_ip(selected_ip);
        }

        if (options->ip_address == NULL) {
            fprintf(stderr, "Error: Unable to resolve IP address for %s\n", selected_ip);
            exit(1);
        }
    } else {
        fprintf(stderr, "Error: Invalid IP index (%d). Must be between 0 and %d.\n", ip_index, options->ip_count - 1);
        exit(1);
    }
}

