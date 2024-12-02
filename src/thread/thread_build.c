#include "ft_nmap.h"

void build_tcp_header_thread(struct tcphdr *tcph, int target_port, int scan_type) {
    tcph->source = htons(20000 + scan_type);  // Port source aléatoire
    tcph->dest = htons(target_port);  // Port cible
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // Longueur de l'en-tête TCP
    if (scan_type == SYN){
        tcph->syn = 1;
    }
    else
        tcph->syn = 0;
    if (scan_type == FIN || scan_type == XMAS) {
        tcph->fin = 1; 
    }
    else
        tcph->fin = 0;   // Flag FIN désactivé
    tcph->rst = 0;   // Flag RST désactivé
    if (scan_type == XMAS){
        tcph->psh = 1;   
        tcph->urg = 1;   
    }
    else{
        tcph->psh = 0;   // Flag PSH désactivé
        tcph->urg = 0;   // Flag URG désactivé
    }
    if (scan_type == ACK) {
        tcph->ack = 1; 
    }
    else
        tcph->ack = 0;   // Flag ACK désactivé
    tcph->window = htons(5840);  // Taille de la fenêtre TCP
    tcph->check = 0;  // Le checksum sera calculé plus tard
    tcph->urg_ptr = 0;  // Pointeur urgent désactivé
}