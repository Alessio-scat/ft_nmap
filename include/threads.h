#ifndef THREADS_H
#define THREADS_H

#include <pthread.h>
#include "ft_nmap.h"

typedef struct {
    int thread_id;       // ID du thread (0 à total_threads - 1)
    int total_threads;   // Nombre total de threads
    int scan_type;
    ScanOptions *options;

    int start_scan;  // Index du scan (type) de départ
    int end_scan;    // Index du scan (type) de fin
    int start_port;  // Port de départ
    int end_port;    // Port de fin
} ThreadData;

void init_threads(ScanOptions *options);
void wait_for_responses(pcap_t *handle, ScanOptions *options);

#endif
