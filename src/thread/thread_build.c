#include "ft_nmap.h"

void build_tcp_header_thread(struct tcphdr *tcph, int target_port, int scan_type) {
    tcph->source = htons(20000 + scan_type);
    tcph->dest = htons(target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    if (scan_type == SYN){
        tcph->syn = 1;
    }
    else
        tcph->syn = 0;
    if (scan_type == FIN || scan_type == XMAS) {
        tcph->fin = 1; 
    }
    else
        tcph->fin = 0; 
    tcph->rst = 0;   
    if (scan_type == XMAS){
        tcph->psh = 1;   
        tcph->urg = 1;   
    }
    else{
        tcph->psh = 0;  
        tcph->urg = 0;   
    }
    if (scan_type == ACK) {
        tcph->ack = 1; 
    }
    else
        tcph->ack = 0;   
    tcph->window = htons(5840);
    tcph->check = 0; 
    tcph->urg_ptr = 0; 
}