#include "ft_nmap.h"

int create_raw_socket();
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest);
void build_tcp_header(struct tcphdr *tcph, int target_port);
void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest);

int create_raw_socket()
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0)
    {
        perror("Error creating raw socket");
        exit(1);
    }
    return sockfd;
}

// Fonction pour construire l'en-tête IP
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321); // ID unique
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Checksum sera calculé après
    iph->saddr = inet_addr(get_local_ip()); // IP source (peut être modifiée)
    iph->daddr = dest->sin_addr.s_addr;

    // Calcul du checksum pour l'en-tête IP
    iph->check = checksum((unsigned short *)iph, iph->tot_len);
}

// Fonction pour construire l'en-tête TCP
void build_tcp_header(struct tcphdr *tcph, int target_port) {
    tcph->source = htons(12345); // Port source (aléatoire)
    tcph->dest = htons(target_port);      // Port cible
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // Longueur de l'en-tête TCP
    tcph->syn = 1;  // Flag SYN activé
    tcph->window = htons(5840); // Taille de fenêtre
    tcph->check = 0; // Checksum sera calculé après
    tcph->urg_ptr = 0;
}

void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest)
{
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Déclare et initialise le pseudo-header pour le calcul du checksum
    psh pshdr;
    pshdr.source_address = iph->saddr; // Adresse IP source
    pshdr.dest_address = dest->sin_addr.s_addr; // Adresse IP destination
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

    // Envoyer le paquet
    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("Échec de l'envoi du paquet");
    } else {
        printf("Paquet envoyé avec succès vers le port %d\n", ntohs(tcph->dest));
    }

    // Libérer la mémoire allouée pour le pseudo-header
    free(pseudogram);
}

void receive_response(int sock)
{
    char buffer[4096];
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);
    int received_bytes;
    while ((received_bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len)) > 0) {
        struct iphdr *iph = (struct iphdr *)buffer; // Pointeur vers l'en-tête IP
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4); // Pointeur vers l'en-tête TCP, après l'en-tête IP

        // Vérifier que le paquet reçu est une réponse TCP
        if (iph->protocol == IPPROTO_TCP) {
            printf("Réponse reçue de %s\n", inet_ntoa(source.sin_addr));

            // Vérifier si c'est une réponse SYN-ACK (port ouvert)
            if (tcph->syn == 1 && tcph->ack == 1) {
                printf("Port %d est ouvert (SYN-ACK reçu)\n", ntohs(tcph->dest));
                break;
            }
            // Vérifier si c'est une réponse RST (port fermé)
            else if (tcph->rst == 1) {
                printf("Port %d est fermé (RST reçu)\n", ntohs(tcph->dest));
                break;
            }
        }
    }

    if (received_bytes < 0) {
        perror("Erreur lors de la réception du paquet");
    }
}

int syn_scan(char *target_ip, int target_port)
{
    printf("localhost %s\n", get_local_ip());
    int sock = create_raw_socket();
    (void)sock;
    // Allocation mémoire pour le paquet
    char packet[4096];
    memset(packet, 0, 4096);

    // Pointeurs vers les en-têtes IP et TCP
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Configuration de la destination
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);  // Port cible
    dest.sin_addr.s_addr = inet_addr(target_ip); // IP cible

    // Construction des en-têtes IP et TCP
    build_ip_header(iph, &dest);
    build_tcp_header(tcph, target_port);
    // Envoi du paquet
    send_packet(sock, packet, iph, &dest);

    // Recevoir et analyser les réponses
    receive_response(sock);

    // Fermeture du socket
    close(sock);
    return 1;
}