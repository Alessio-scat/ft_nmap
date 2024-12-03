#include "../include/ft_nmap.h"

void signal_handler(int signum) {
    if (signum == SIGINT) {

        if (global_options != NULL)
            cleanup_options(global_options);

        if (global_handle) {
            pcap_breakloop(global_handle);
            pcap_close(global_handle);
            global_handle = NULL;
        }

        exit(0);
    }
}