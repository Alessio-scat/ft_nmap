#include "../include/ft_nmap.h"

void signal_handler(int signum) {
    if (signum == SIGINT) {

        if (global_options != NULL) {
            // if (global_options->local_interface)
            //     free(global_options->local_interface);
            // if (global_options->local_ip)
            //     free(global_options->local_ip);
            // if (global_options->ip_host)
            //     free(global_options->ip_host);
            // if (global_options->ip_address)
            //     free(global_options->ip_address);

            // for (int j = 0; j < global_options->ip_count; j++)
            //     free(global_options->ip_list[j]);
            // free(global_options->ip_list);
            // for (int i = 0; i < global_options->scan_count; i++) {
            //     for (int j = 0; j < MAX_PORT; j++) {
            //         if (global_options->status[i][j] != NULL) {
            //             free(global_options->status[i][j]);
            //         }
            //     }
            //     free(global_options->status[i]);
            // }
            // free(global_options->status);
            // free_nmap(global_options);
            cleanup_options(global_options);

        }

        if (global_handle) {
            pcap_breakloop(global_handle);
            pcap_close(global_handle);
            global_handle = NULL;
        }

        exit(0);
    }
}