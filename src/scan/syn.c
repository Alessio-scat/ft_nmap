#include "ft_nmap.h"

int create_raw_socket();
void build_ip_header(void *iph, struct sockaddr_in *dest);
void build_tcp_header(struct tcphdr *tcph, int target_port);
void send_packet(int sock, char *packet, void *iph, struct sockaddr_in *dest);

void print_tcphdr(struct tcphdr *tcph) {
    printf("=== En-tête TCP ===\n");
#ifdef __APPLE__
    printf("Source Port: %d\n", ntohs(tcph->th_sport));        // Port source sur macOS
    printf("Destination Port: %d\n", ntohs(tcph->th_dport));   // Port destination sur macOS
    printf("Sequence Number: %u\n", ntohl(tcph->th_seq));      // Numéro de séquence sur macOS
    printf("Acknowledgment Number: %u\n", ntohl(tcph->th_ack));  // Numéro d'accusé de réception sur macOS
    printf("Data Offset: %d\n", tcph->th_off * 4);             // Longueur de l'en-tête TCP sur macOS
    printf("Flags: \n");
    printf("   SYN: %d\n", (tcph->th_flags & TH_SYN) != 0);    // Flag SYN sur macOS
    printf("   ACK: %d\n", (tcph->th_flags & TH_ACK) != 0);    // Flag ACK sur macOS
    printf("   RST: %d\n", (tcph->th_flags & TH_RST) != 0);    // Flag RST sur macOS
    printf("   FIN: %d\n", (tcph->th_flags & TH_FIN) != 0);    // Flag FIN sur macOS
    printf("   PSH: %d\n", (tcph->th_flags & TH_PUSH) != 0);   // Flag PSH sur macOS
    printf("   URG: %d\n", (tcph->th_flags & TH_URG) != 0);    // Flag URG sur macOS
    printf("Window Size: %d\n", ntohs(tcph->th_win));          // Taille de la fenêtre sur macOS
    printf("Checksum: 0x%x\n", ntohs(tcph->th_sum));           // Checksum TCP sur macOS
    printf("Urgent Pointer: %d\n", tcph->th_urp);              // Pointeur urgent sur macOS
#else
    printf("Source Port: %d\n", ntohs(tcph->source));          // Port source sur Linux
    printf("Destination Port: %d\n", ntohs(tcph->dest));       // Port destination sur Linux
    printf("Sequence Number: %u\n", ntohl(tcph->seq));         // Numéro de séquence sur Linux
    printf("Acknowledgment Number: %u\n", ntohl(tcph->ack_seq)); // Numéro d'accusé de réception sur Linux
    printf("Data Offset: %d\n", tcph->doff * 4);               // Longueur de l'en-tête TCP sur Linux
    printf("Flags: \n");
    printf("   SYN: %d\n", tcph->syn);                         // Flag SYN sur Linux
    printf("   ACK: %d\n", tcph->ack);                         // Flag ACK sur Linux
    printf("   RST: %d\n", tcph->rst);                         // Flag RST sur Linux
    printf("   FIN: %d\n", tcph->fin);                         // Flag FIN sur Linux
    printf("   PSH: %d\n", tcph->psh);                         // Flag PSH sur Linux
    printf("   URG: %d\n", tcph->urg);                         // Flag URG sur Linux
    printf("Window Size: %d\n", ntohs(tcph->window));          // Taille de la fenêtre sur Linux
    printf("Checksum: 0x%x\n", ntohs(tcph->check));            // Checksum TCP sur Linux
    printf("Urgent Pointer: %d\n", tcph->urg_ptr);             // Pointeur urgent sur Linux
#endif
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

void build_ip_header(void *iph, struct sockaddr_in *dest) {
#ifdef __APPLE__
    struct ip *ip_hdr = (struct ip *)iph;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4; 
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr)); // Total length
    ip_hdr->ip_id = htons(54321); // Utilisation de htons pour éviter la conversion 32-bit
    ip_hdr->ip_off = 0; 
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_sum = 0;
    printf("ici\n");
    ip_hdr->ip_src.s_addr = inet_addr(get_local_ip());
    printf("tac\n");
    ip_hdr->ip_dst = dest->sin_addr;
#else
    struct iphdr *ip_hdr = (struct iphdr *)iph;
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_hdr->id = htonl(54321);
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 255;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->check = 0;
    ip_hdr->saddr = inet_addr(get_local_ip()); 
    ip_hdr->daddr = dest->sin_addr.s_addr;
#endif
}



void build_tcp_header(struct tcphdr *tcph, int target_port) {
#ifdef __APPLE__
    tcph->th_sport = htons(rand() % 65535 + 1024);
    tcph->th_dport = htons(target_port);
    tcph->th_seq = 0;
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(5840); 
    tcph->th_sum = 0;
    tcph->th_urp = 0;
#else
    tcph->source = htons(rand() % 65535 + 1024);
    tcph->dest = htons(target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(5840);
    tcph->check = 0; 
    tcph->urg_ptr = 0;
#endif
}


void send_packet(int sock, char *packet, void *iph, struct sockaddr_in *dest)
{
#ifdef __APPLE__
    struct ip *ip_hdr = (struct ip *)iph;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
#else
    struct iphdr *ip_hdr = (struct iphdr *)iph;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));  // Utilisation de struct iphdr sur Linux
#endif

    // Déclare et initialise le pseudo-header pour le calcul du checksum
    psh pshdr;
    pshdr.source_address = ip_hdr->ip_src.s_addr;  // Source IP
    pshdr.dest_address = ip_hdr->ip_dst.s_addr;    // Destination IP
    pshdr.placeholder = 0;                         // Champ de remplissage
    pshdr.protocol = IPPROTO_TCP;                  // Protocole TCP
    pshdr.tcp_length = htons(sizeof(struct tcphdr));  // Longueur de l'en-tête TCP

    // Taille totale pour le calcul du checksum (pseudo-header + en-tête TCP)
    int psize = sizeof(psh) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    // Copier le pseudo-header et l'en-tête TCP dans le buffer pour le calcul
    memcpy(pseudogram, (char *)&pshdr, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));

    // Calculer le checksum TCP en utilisant le pseudo-header et l'en-tête TCP
#ifdef __APPLE__
    tcph->th_sum = checksum((unsigned short *)pseudogram, psize);  // Utilisation de th_sum sur macOS
#else
    tcph->check = checksum((unsigned short *)pseudogram, psize);   // Utilisation de check sur Linux
#endif

    // Envoyer le paquet
#ifdef __APPLE__
    if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
#else
    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
#endif
        perror("Échec de l'envoi du paquet");
    } else {
#ifdef __APPLE__
        printf("Paquet envoyé avec succès vers le port %d\n", ntohs(tcph->th_dport));  // Utilisation de th_dport sur macOS
#else
        printf("Paquet envoyé avec succès vers le port %d\n", ntohs(tcph->dest));  // Utilisation de dest sur Linux
#endif
    }

    // Libérer la mémoire allouée pour le pseudo-header
    free(pseudogram);
}




void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)pkthdr;  // Paramètre inutilisé

#ifdef __APPLE__
    struct ip *ip_hdr = (struct ip *)(packet + 14);  // Saut de l'en-tête Ethernet (14 octets)
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + ip_hdr->ip_hl * 4);  // En-tête TCP sur macOS
#else
    struct iphdr *ip_hdr = (struct iphdr *)(packet + 14);  // En-tête IP sur Linux
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + ip_hdr->ihl * 4);  // En-tête TCP sur Linux
#endif

    int target_port = *(int *)user_data;

#ifdef __APPLE__
    if (ip_hdr->ip_p == IPPROTO_TCP && ntohs(tcph->th_sport) == target_port) {  // Vérification du port source sur macOS
#else
    if (ip_hdr->protocol == IPPROTO_TCP && ntohs(tcph->source) == target_port) {  // Vérification du port source sur Linux
#endif
        printf("Réponse TCP reçue du port %d\n", target_port);

#ifdef __APPLE__
        // Sous macOS, les flags TCP sont dans le champ `th_flags`
        if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {  // Vérification des flags SYN et ACK
#else
        if (tcph->syn == 1 && tcph->ack == 1) {  // Vérification des flags SYN et ACK sur Linux
#endif
            printf("Port %d est ouvert (SYN-ACK reçu)\n", target_port);
            pcap_breakloop((pcap_t *)user_data);  // Sortir de la boucle de capture
        }
#ifdef __APPLE__
        else if (tcph->th_flags & TH_RST) {  // Vérification du flag RST sur macOS
#else
        else if (tcph->rst == 1) {  // Vérification du flag RST sur Linux
#endif
            printf("Port %d est fermé (RST reçu)\n", target_port);
            pcap_breakloop((pcap_t *)user_data);  // Sortir de la boucle de capture
        }
    }
}


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
#ifdef __APPLE__
    struct ip *iph = (struct ip *)packet;  // Utilisation de struct ip sur macOS
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));  // Calcul correct de l'offset TCP sur macOS
#else
    struct iphdr *iph = (struct iphdr *)packet;  // Utilisation de struct iphdr sur Linux
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));  // Calcul correct de l'offset TCP sur Linux
#endif

    // Configuration de la destination
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);  // Port cible
    dest.sin_addr.s_addr = inet_addr(target_ip);  // IP cible

    printf("%s\n", target_ip);

    // Construction des en-têtes IP et TCP
    build_ip_header(iph, &dest);  // Fonction qui adapte selon l'OS
    build_tcp_header(tcph, target_port);  // Fonction qui adapte selon l'OS
    // Envoi du paquet
    send_packet(sock, packet, iph, &dest);
    // Recevoir et analyser les réponses
    // receive_response(sock, target_port);

    // Utiliser libpcap pour capturer la réponse
    receive_response_pcap("en0", target_port);
    printf("33\n");
    // Fermeture du socket
    close(sock);
    return 1;
}

