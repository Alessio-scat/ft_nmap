#include "ft_nmap.h"

int create_raw_socket();
void build_ip_header(struct iphdr *iph, struct sockaddr_in *dest);
void build_tcp_header(struct tcphdr *tcph, int target_port);
void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest);

void print_tcphdr(struct tcphdr *tcph) {
    printf("=== En-tête TCP ===\n");
    printf("Source Port: %d\n", ntohs(tcph->source));        // Port source
    printf("Destination Port: %d\n", ntohs(tcph->dest));      // Port destination
    printf("Sequence Number: %u\n", ntohl(tcph->seq));        // Numéro de séquence
    printf("Acknowledgment Number: %u\n", ntohl(tcph->ack_seq));  // Numéro d'accusé de réception
    printf("Data Offset: %d\n", tcph->doff * 4);              // Longueur de l'en-tête TCP
    printf("Flags: \n");
    printf("   SYN: %d\n", tcph->syn);                        // Flag SYN
    printf("   ACK: %d\n", tcph->ack);                        // Flag ACK
    printf("   RST: %d\n", tcph->rst);                        // Flag RST
    printf("   FIN: %d\n", tcph->fin);                        // Flag FIN
    printf("   PSH: %d\n", tcph->psh);                        // Flag PSH
    printf("   URG: %d\n", tcph->urg);                        // Flag URG
    printf("Window Size: %d\n", ntohs(tcph->window));         // Taille de la fenêtre
    printf("Checksum: 0x%x\n", ntohs(tcph->check));           // Checksum TCP
    printf("Urgent Pointer: %d\n", tcph->urg_ptr);            // Pointeur urgent
    printf("===================\n");
}

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
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
}

// Fonction pour construire l'en-tête TCP
void build_tcp_header(struct tcphdr *tcph, int target_port) {
    tcph->source = htons(rand() % 65535 + 1024);  // Port source (aléatoire)
    tcph->dest = htons(target_port);  // Port cible
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // Longueur de l'en-tête TCP
    tcph->syn = 1;  // Flag SYN activé
    tcph->window = htons(5840);  // Taille de la fenêtre
    tcph->check = 0;  // Le checksum sera calculé plus tard
    tcph->urg_ptr = 0;
}

void send_packet(int sock, char *packet, struct iphdr *iph, struct sockaddr_in *dest)
{
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
    
    // Envoyer le paquet
    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("Échec de l'envoi du paquet");
    } else {
        printf("Paquet envoyé avec succès vers le port %d\n", ntohs(tcph->dest));
    }

    // Libérer la mémoire alloué pour le pseudo-header
    free(pseudogram);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;  // Paramètre inutilisé

    struct iphdr *iph = (struct iphdr *)(packet + 14);  // Saut de l'en-tête Ethernet (14 octets)
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ihl * 4);  // En-tête TCP

    int target_port = *(int *)user_data;
    printf("ici\n");
    // printf("%d et %d\n", target_port, ntohs(tcph->source));
    // Vérifie que c'est un paquet TCP et que le port source correspond au port scanné
    if (iph->protocol == IPPROTO_TCP && ntohs(tcph->source) == target_port) {
        printf("Réponse TCP reçue du port %d\n", ntohs(tcph->source));

        // Vérifier les flags SYN-ACK ou RST
        if (tcph->syn == 1 && tcph->ack == 1) {
            printf("Port %d est ouvert (SYN-ACK reçu)\n", ntohs(tcph->source));
            pcap_breakloop((pcap_t *)user_data);  // Sortir de la boucle de capture
        }
        else if (tcph->rst == 1) {
            printf("Port %d est fermé (RST reçu)\n", ntohs(tcph->source));
            pcap_breakloop((pcap_t *)user_data);  // Sortir de la boucle de capture
        }
    }
}

// void receive_response(int sock, int target_port)
// {
//     char buffer[4096];
//     struct sockaddr_in source;
//     socklen_t source_len = sizeof(source);
//     int received_bytes;
//     while ((received_bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len)) > 0) {
//         struct iphdr *iph = (struct iphdr *)buffer; // Pointeur vers l'en-tête IP
//         struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4); // Pointeur vers l'en-tête TCP, après l'en-tête IP

//         // Vérifier que le paquet reçu est une réponse TCP
//         printf("%d et %d \n",ntohs(tcph->source), target_port);
//         if (iph->protocol == IPPROTO_TCP && ntohs(tcph->source) == target_port) {
//             printf("Réponse reçue de %s\n", inet_ntoa(source.sin_addr));
//             // print_tcphdr(tcph);
//             // Vérifier si c'est une réponse SYN-ACK (port ouvert)
//             if (tcph->syn == 1 && tcph->ack == 1) {
//                 printf("Port %d est ouvert (SYN-ACK reçu)\n", ntohs(tcph->source));
//                 break;
//             }
//             // Vérifier si c'est une réponse RST (port fermé)
//             else if (tcph->rst == 1) {
//                 printf("Port %d est fermé (RST reçu)\n", ntohs(tcph->source));
//                 break;
//             }
//         }
//     }

//     if (received_bytes < 0) {
//         perror("Erreur lors de la réception du paquet");
//     }
// }

void receive_response_pcap(char *interface, int target_port) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // bpf_u_int32 net = 0;  // Initialiser à 0

    // Ouvrir l'interface pour capturer les paquets
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Impossible d'ouvrir l'interface : %s\n", errbuf);
        return;
    }
    struct bpf_program fp;
    char filter_exp[50];
    sprintf(filter_exp, "tcp and src port %d", target_port);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Erreur de compilation du filtre : %s\n", pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Erreur d'application du filtre : %s\n", pcap_geterr(handle));
        return;
    }

    // Supprimer le filtre pour capturer tous les paquets TCP
    printf("Capturer tous les paquets sur l'interface %s\n", interface);

    // Commencer à capturer les paquets
    pcap_loop(handle, 10, packet_handler, (u_char *)&target_port);

    // Fermer le handle pcap
    pcap_close(handle);
}




int syn_scan(char *target_ip, int target_port)
{
    printf("localhost %s\n", get_local_ip());
    int sock = create_raw_socket();
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

    printf("%s\n", target_ip );

    // Construction des en-têtes IP et TCP
    build_ip_header(iph, &dest);
    build_tcp_header(tcph, target_port);
    // Envoi du paquet
    send_packet(sock, packet, iph, &dest);

    // Recevoir et analyser les réponses
    // receive_response(sock, target_port);

    // Utiliser libpcap pour capturer la réponse
    receive_response_pcap("eth0", target_port);

    // Fermeture du socket
    close(sock);
    return 1;
}