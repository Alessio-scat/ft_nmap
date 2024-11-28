#include "ft_nmap.h"



void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest) {
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Déclare et initialise le pseudo-header pour le calcul du checksum
    psh pshdr;
    pshdr.source_address = iph->saddr; // Adresse IP source
    pshdr.dest_address = iph->daddr; // Adresse IP destination
    pshdr.placeholder = 0; // Champ de remplissage
    pshdr.protocol = IPPROTO_TCP; // Protocole TCP
    pshdr.tcp_length = htons(sizeof(struct tcphdr)); // Longueur de l'en-tête TCP

    // Taille totale pour le calcul du checksum (pseudo-header + en-tête TCP)
    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    // Copier le pseudo-header et l'en-tête TCP dans le buffer pour le calcul
    memcpy(pseudogram, (char *)&pshdr, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));

    // Calculer le checksum TCP en utilisant le pseudo-header et l'en-tête TCP
    tcph->check = checksum((unsigned short *)pseudogram, psize);

    // printf("Envoi d'un paquet SYN vers %s:%d\n", inet_ntoa(dest->sin_addr), ntohs(tcph->dest));

    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        // print_tcphdr(tcph);
        perror("Échec de l'envoi du paquet");
    }
    free(pseudogram);
}

// void send_all_packets(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {

//     for (int j = 0; j < options->portsTabSize; j++) {
//         int target_port = options->portsTab[j];
//         // printf("%d\n", options->portsTabSize);
//         // printf("%d\n", target_port);
//         dest->sin_port = htons(target_port);

//         if (options->scan_type == UDP){
//             memset(packet, 0, 4096);

//             // Construire les en-têtes IP et UDP
//             struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

//             build_udp_header_udp(udph, target_port);

//             // Envoyer le paquet personnalisé
//             if (sendto(sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
//                 perror("Failed to send UDP packet");
//             }
//         }else{
//             // Construire l'en-tête TCP pour chaque port
//             build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);

//             // Envoyer le paquet SYN
//             send_packet(sock, packet, iph, dest);
//         }

//         // Petit délai entre les envois pour ne pas saturer le réseau
//         usleep(1000);
//     }
// }

void send_all_packets(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest, ScanOptions *options) {
    for (int j = 0; j < options->portsTabSize; j++) {
        int target_port = options->portsTab[j];

        dest->sin_port = htons(target_port); // Définir le port cible

        if (options->scan_type == UDP) {
            // Initialiser les en-têtes IP et UDP
            memset(packet, 0, 4096); // Nettoyer le buffer
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

            build_udp_header_udp(udph, target_port);

            // Envoyer le paquet
            if (sendto(sock, packet, htons(iph->tot_len), 0,
                       (struct sockaddr *)dest, sizeof(*dest)) < 0) {
                perror("Failed to send UDP packet");
            }
        } else {
            // Construire et envoyer les paquets TCP
            build_tcp_header((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, options);
            send_packet(sock, packet, iph, dest);
        }

        // Petit délai entre les envois
        usleep(1000);
    }
}
