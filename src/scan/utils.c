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

void initialize_status(ScanOptions *options, int num_techniques, int num_ports) {
    // Allouer de la mémoire pour chaque technique (première dimension)
    options->status = malloc(num_techniques * sizeof(char **));
    if (options->status == NULL) {
        perror("Failed to allocate memory for techniques");
        exit(1);
    }

    // Pour chaque technique, allouer la mémoire pour les statuts des ports (deuxième dimension)
    for (int i = 0; i < num_techniques; i++)
    {
        options->status[i] = malloc(num_ports * sizeof(char *));
        if (options->status[i] == NULL)
        {
            perror("Failed to allocate memory for ports");
            exit(1);
        }

        for (int j = 0; j < num_ports; j++)
        {
            options->status[i][j] = malloc(10 * sizeof(char)); // Taille maximale pour chaque statut
            if (options->status[i][j] == NULL)
            {
                perror("Failed to allocate memory for status entry");
                exit(1);
            }
            strcpy(options->status[i][j], "FILTERED");
        }
    }

    // Mettre à jour la taille des ports
    // options->portsTabSize = num_ports;
}

void print_ports_excluding_state(ScanOptions *options, const char *excluded_state) {
    printf("Results for %s(%s)\n", options->ip_host, options->ip_address);
    int excluded_count = 0;

    // Comptage des ports dans l'état spécifié (par exemple, "CLOSED")
    for (int i = 0; i < options->portsTabSize; i++) {
        for (int technique = 0; technique < 1; technique++) {  // Si tu as plusieurs techniques, il faut boucler dessus
            if (strcmp(options->status[technique][i], excluded_state) == 0) {
                excluded_count++;
            }
        }
    }

    // Affichage du nombre de ports dans l'état exclu
    printf("%d ports on state %s\n", excluded_count, excluded_state);

    // Affichage des détails des ports qui ne sont pas dans cet état exclu
    printf("    PORT    SERVICE         STATE\n");
    for (int i = 0; i < options->portsTabSize; i++) {
        for (int technique = 0; technique < 1; technique++) {
            if (strcmp(options->status[technique][options->portsTab[i] - 1], excluded_state) != 0 || options->flag_ports == 1) {  // On affiche les ports qui ne sont pas dans l'état exclu
                // Obtenir le nom du service pour le port
                struct servent *service_entry = getservbyport(htons(options->portsTab[i]), "tcp");
                const char *service_name = (service_entry != NULL) ? service_entry->s_name : "unknown";

                // Afficher les détails du port
                printf("    %5d    %-15s  %s\n", options->portsTab[i], service_name, options->status[technique][options->portsTab[i] - 1]);
            }
        }
    }
}