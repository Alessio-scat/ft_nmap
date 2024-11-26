#ifndef THREADS_H
#define THREADS_H

#include <pthread.h>
#include "ft_nmap.h"

typedef struct {
    int thread_id;       // ID du thread (0 à total_threads - 1)
    int total_threads;   // Nombre total de threads
    ScanOptions *options;
} ThreadData;

void *thread_worker(void *arg);

#endif
