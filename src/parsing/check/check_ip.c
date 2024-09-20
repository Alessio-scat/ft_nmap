#include "../../../include/ft_nmap.h"

int validate_ip_or_hostname(char *input) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, input, &(sa.sin_addr)) == 1)
        return 1; // Valid IP address
    // Regular expression for validating FQDNs

    const char *regex_pattern = "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
    regex_t regex;
    int ret;
    ret = regcomp(&regex, regex_pattern, REG_EXTENDED);

    if (ret)
        exit(EXIT_FAILURE);

    ret = regexec(&regex, input, 0, NULL, 0);
    regfree(&regex);
    
    if (ret == 0)
        return 1; //Ip valid
    else
        return 0;
}

// Handle the --ip option
void handle_ip_option(int *i, int ac, char **av, ScanOptions *options) {
    if (*i + 1 < ac) {
        if (validate_ip_or_hostname(av[*i + 1])) {
            options->ip_address = av[*i + 1];
            (*i)++;
        } else {
            fprintf(stderr, "Error: Invalid IP address or hostname: %s\n", av[*i + 1]); exit(1);
        }
    } else {
        fprintf(stderr, "Error: --ip option requires an IP address or hostname.\n"); exit(1);
    }
}