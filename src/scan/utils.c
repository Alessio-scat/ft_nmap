#include "ft_nmap.h"

// Fonction pour afficher le résultat formaté
void print_scan_result(int port, const char *service, const char *state) {
    printf("        %-7d%-15s%-10s\n", port, service, state);
}


// Fonction pour calculer le checksum
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

// Fonction pour récupérer l'adresse IP locale
char *get_local_ip() {
    struct ifaddrs *ifap, *ifa;
    char *addr = NULL;

    if (getifaddrs(&ifap) < 0) {
        perror("getifaddrs");
        exit(1);
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        // Vérifier si c'est une interface IPv4
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            // Ignorer les interfaces inactives ou l'interface de boucle locale (lo)
            if ((ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
                // Copier l'adresse IP si l'interface est active et pas la loopback
                addr = strdup(inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
                printf("Interface: %s, IP: %s\n", ifa->ifa_name, addr);
                break;  // Si tu veux seulement la première IP, sinon ne pas mettre break
            }
        }
    }

    freeifaddrs(ifap);
    return addr;
}

char *get_local_interface() {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *local_interface = NULL;

    // Récupère toutes les interfaces réseau disponibles
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erreur lors de la récupération des interfaces : %s\n", errbuf);
        return NULL;
    }

    // Parcours la liste des interfaces pour trouver une interface valide
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->flags & PCAP_IF_UP) { // Vérifie si l'interface est active (up)
            // Copie le nom de l'interface dans local_interface
            local_interface = strdup(dev->name);
            break;
        }
    }

    // Libère la liste des interfaces
    pcap_freealldevs(alldevs);

    // Si aucune interface n'a été trouvée
    if (local_interface == NULL) {
        fprintf(stderr, "Aucune interface réseau active trouvée\n");
    }

    return local_interface;
}
