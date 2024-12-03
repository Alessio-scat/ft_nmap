#include "ft_nmap.h"

void *threaded_scan(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;

    // Create a local buffer per thread
    char packet[4096];
    memset(packet, 0, 4096);
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in dest = data->dest;

    for (int scan = data->start_scan; scan < data->end_scan; scan++) {
        int scan_type = data->options->tabscan[scan]; // Use a local copy

        int sock;
        if (scan_type == 6) {
            sock = create_udp_socket();
            build_ip_header_udp(iph, &dest, data->options);
        } else {
            sock = create_raw_socket();
            build_ip_header(iph, &dest, data->options);
        }

        for (int j = data->start_port; j < data->end_port; j++) {
            int target_port = data->options->portsTab[j];
            dest.sin_port = htons(target_port);

            if (scan_type == UDP) {
                struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
                build_udp_header_udp(udph, target_port);
                if (sendto(sock, packet, htons(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                    perror("Failed to send UDP packet");
                }
            } else {
                build_tcp_header_thread((struct tcphdr *)(packet + sizeof(struct iphdr)), target_port, scan_type);
                send_packet(sock, packet, iph, &dest);
            }
            usleep(1000);
        }
        close(sock);
    }
    pthread_exit(NULL);
}