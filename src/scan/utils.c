#include "ft_nmap.h"

// Function to display formatted result
void print_scan_result(int port, const char *service, const char *state) {
    printf("        %-7d%-15s%-10s\n", port, service, state);
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

char *get_local_ip(int use_loopback, ScanOptions *options) {

    if (options->local_ip) {
        free(options->local_ip);
        options->local_ip = NULL;
    }

    struct ifaddrs *ifap, *ifa;
    char *addr = NULL;

    if (getifaddrs(&ifap) < 0) {
        perror("getifaddrs");
        exit(1);
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        // check if it's IPv4
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            // If use_loopback is enabled, returns the loopback IP address (127.0.0.1)
            if (use_loopback && (ifa->ifa_flags & IFF_LOOPBACK)) {
                addr = strdup(inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
                break;
            }

            // Otherwise, ignore the loopback and take an active non-loopback interface
            if ((ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
                addr = strdup(inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
                break;
            }
        }
    }

    freeifaddrs(ifap);
    return addr;
}


char *get_local_interface(int use_loopback, ScanOptions *options) {

    if (options->local_interface) {
        free(options->local_interface);
        options->local_interface = NULL;
    }

    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *local_interface = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error retrieving interfaces: %s\n", errbuf);
        return NULL;
    }

    // Force interface loopback if `use_loopback` is defined
    if (use_loopback) {
        local_interface = strdup("lo");
    } else {
        // Go through the list of interfaces to find a valid interface other than loopback
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            if (dev->flags & PCAP_IF_UP && !(dev->flags & PCAP_IF_LOOPBACK)) {
                local_interface = strdup(dev->name);
                break;
            }
        }
    }

    pcap_freealldevs(alldevs);

    if (local_interface == NULL) {
        fprintf(stderr, "No active network interface found\n");
    }

    return local_interface;
}

void initialize_status(ScanOptions *options, int num_techniques, int num_ports) {
    if (num_techniques <= 0 || num_ports <= 0) {
        fprintf(stderr, "Invalid dimensions: num_techniques=%d, num_ports=%d\n", num_techniques, num_ports);
        exit(1);
    }

    options->status = malloc(num_techniques * sizeof(char **));
    if (options->status == NULL) {
        perror("Failed to allocate memory for techniques");
        exit(1);
    }

    for (int i = 0; i < num_techniques; i++) {
        options->status[i] = malloc(num_ports * sizeof(char *));
        if (options->status[i] == NULL) {
            for (int k = 0; k < i; k++) {
                free(options->status[k]);
            }
            free(options->status);
            perror("Failed to allocate memory for ports");
            exit(1);
        }

        for (int j = 0; j < num_ports; j++) {
            options->status[i][j] = malloc(15 * sizeof(char));
            if (options->status[i][j] == NULL) {
                for (int l = 0; l < j; l++) {
                    free(options->status[i][l]);
                }
                free(options->status[i]);
                for (int k = 0; k < i; k++) {
                    free(options->status[k]);
                }
                free(options->status);
                perror("Failed to allocate memory for status entry");
                exit(1);
            }

            if (options->tabscan[i] == 6) {
                strncpy(options->status[i][j], "OPEN|FILTERED", 14);
                options->status[i][j][14] = '\0';
            } else if (options->tabscan[i] == 2 || options->tabscan[i] == 3 || options->tabscan[i] == 4) {
                strncpy(options->status[i][j], "OPEN|FILTERED", 14);
                options->status[i][j][14] = '\0';
            } else {
                strncpy(options->status[i][j], "FILTERED", 14);
                options->status[i][j][14] = '\0';
            }
        }
    }
}

void reset_status(ScanOptions *options, int scan_count, int max_ports) {
    for (int i = 0; i < scan_count; i++) {
        for (int j = 0; j < max_ports; j++) {
            // Reset based on tabscan value
            if (options->tabscan[i] == 6) {
                strcpy(options->status[i][j], "OPEN|FILTERED");
            } else if (options->tabscan[i] == 2 || options->tabscan[i] == 3 || options->tabscan[i] == 4) {
                strcpy(options->status[i][j], "OPEN|FILTERED");
            } else {
                strcpy(options->status[i][j], "FILTERED");
            }
        }
    }
}



