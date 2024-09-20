#include "../../../include/ft_nmap.h"

int validate_ports(char *ports) {
    regex_t regex;
    int ret = regcomp(&regex, "^([0-9]+(-[0-9]+)?)(,[0-9]+(-[0-9]+)?)*$", REG_EXTENDED);
    if (ret) {
        return 0;
    }
    ret = regexec(&regex, ports, 0, NULL, 0);
    regfree(&regex);
    if (ret == 0)
        return 1; //Ip valid
    else
        return 0;
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