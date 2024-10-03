#include "ft_nmap.h"

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
// char *get_local_ip() {
//     struct ifaddrs *ifap;
// 	struct ifaddrs *ifa;
// 	char *addr;

// 	addr = NULL;
// 	if (getifaddrs(&ifap) < 0)
//     {
// 		perror("getifaddrs");
//         exit(1);
//     }
// 	ifa = ifap;
// 	while (ifa->ifa_next != NULL)
// 	{
// 		if (ifa->ifa_addr->sa_family == AF_INET &&
// 			(strcmp("eth0", ifa->ifa_name) == 0 || strcmp("enp0s3", ifa->ifa_name) == 0))
// 		{
// 			addr = strdup(inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr));
// 			break;
// 		}
// 		ifa = ifa->ifa_next;
// 	}
// 	freeifaddrs(ifap);
// 	return (addr);
// }
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
