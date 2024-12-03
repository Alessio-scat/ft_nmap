#include "../include/ft_nmap.h"

void free_nmap(ScanOptions *options){
    if (options->local_interface)
        free(options->local_interface);
    if (options->local_ip)
        free(options->local_ip);
    if (options->ip_host)
        free(options->ip_host);
    if (options->ip_address)
        free(options->ip_address);

    for (int j = 0; j < options->ip_count; j++)
        free(options->ip_list[j]);
    free(options->ip_list);
    for (int i = 0; i < options->scan_count; i++) {
        for (int j = 0; j < MAX_PORT; j++) {
            if (options->status[i][j] != NULL) {
                free(options->status[i][j]);
            }
        }
        free(options->status[i]);
    }
    free(options->status);
}

void cleanup_options(ScanOptions *options) {

     if (options->local_interface)
        free(options->local_interface);
    
    if (options->local_ip)
        free(options->local_ip);
    
    if (options->ip_host) {
        free(options->ip_host);
        options->ip_host = NULL;
    }
    if (options->ip_address) {
        free(options->ip_address);
        options->ip_address = NULL;
    }
    // if (options->file) {
    //     free(options->file);
    //     options->file = NULL;
    // }
    if (options->ip_list) {
        for (int i = 0; i < options->ip_count; i++) {
            free(options->ip_list[i]);
        }
        free(options->ip_list);
        options->ip_list = NULL;
    }

    if (options->status) {
        for (int i = 0; i < options->scan_count; i++) {
            if (options->status[i] != NULL) {
                for (int j = 0; j < MAX_PORT; j++) {
                    if (options->status[i][j] != NULL) {
                        free(options->status[i][j]);
                        options->status[i][j] = NULL;
                    }
                }
                free(options->status[i]);
                options->status[i] = NULL;
            }
        }
        free(options->status);
        options->status = NULL;
    }
}

