#include "ft_nmap.h"

void thread_smaller_than_scan(ScanOptions *options) {
    int num_threads = options->speedup;
    pthread_t threads[num_threads];
    ScanThreadData thread_data[num_threads];

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Total combinations (scans x ports)
    int total_combinations = options->scan_count * options->portsTabSize;
    int combinations_per_thread = total_combinations / num_threads;
    int extra_combinations = total_combinations % num_threads;

    int current_combination = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].options = options;
        thread_data[i].dest = dest;

        // Calculate combinations for this thread
        int start_combination = current_combination;
        int end_combination = start_combination + combinations_per_thread + (i < extra_combinations ? 1 : 0);

        // If this is the last thread, include all remaining combinations
        if (i == num_threads - 1) {
            end_combination = total_combinations;
        }

        current_combination = end_combination;

        // Split scans and ports
        thread_data[i].start_scan = start_combination / options->portsTabSize;
        thread_data[i].end_scan = end_combination / options->portsTabSize;

        thread_data[i].start_port = start_combination % options->portsTabSize;
        thread_data[i].end_port = end_combination % options->portsTabSize;

        // If the thread covers multiple scans, adjust the ports
        if (thread_data[i].start_scan != thread_data[i].end_scan) {
            thread_data[i].start_port = 0;              
            thread_data[i].end_port = options->portsTabSize; 
        }

        // If this is the last thread and the ports need to expand
        if (i == num_threads - 1) {
            thread_data[i].end_scan = options->scan_count;
            thread_data[i].end_port = options->portsTabSize;
        }
        if(thread_data[i].start_scan == thread_data[i].end_scan)
            thread_data[i].end_scan++;
        // printf("Thread %d: scans [", i);
        //     for (int scan_id = thread_data[i].start_scan; scan_id < thread_data[i].end_scan; scan_id++) {
        //         printf("%s", get_scan_name(options->tabscan[scan_id]));
        //         if (scan_id < thread_data[i].end_scan - 1) {
        //             printf(", ");
        //         }
        //     }
        // printf("], ports [%d, %d)\n", 
        //     thread_data[i].start_port, 
        //     thread_data[i].end_port);

        // Create the thread
        if (pthread_create(&threads[i], NULL, threaded_scan, &thread_data[i]) != 0) {
            perror("Failed to create thread");
            exit(1);
        }
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
}

void run_scans_by_techniques(ScanOptions *options) {
    int max_threads = options->scan_count * options->portsTabSize;
    if (options->speedup > max_threads) {
        printf("Number of threads requested (%d) exceeds the maximum necessary (%d). Automatic limitation to %d threads.\n", 
               options->speedup, max_threads, max_threads);
        options->speedup = max_threads; // Reduce to the minimum necessary
    }
    if (options->speedup < options->scan_count) {
        thread_smaller_than_scan(options);
        return;
    }

    int num_threads = options->speedup; 
    pthread_t threads[num_threads];
    ScanThreadData thread_data[num_threads];

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(options->ip_address);

    // Calculate ports per scan and associated threads
    int threads_per_scan = num_threads / options->scan_count;
    int extra_threads = num_threads % options->scan_count;

    int thread_index = 0;

    for (int scan_index = 0; scan_index < options->scan_count; scan_index++) {
        // Number of threads for this scan
        int threads_for_this_scan = threads_per_scan + (scan_index < extra_threads ? 1 : 0);

        // Ports per thread for this scan
        int ports_per_thread = options->portsTabSize / threads_for_this_scan;
        int extra_ports = options->portsTabSize % threads_for_this_scan;

        int current_start_port = 0;

        for (int i = 0; i < threads_for_this_scan; i++) {
            thread_data[thread_index].thread_id = thread_index;
            thread_data[thread_index].options = options;

            thread_data[thread_index].dest = dest;

            // Assign scan to this thread
            thread_data[thread_index].start_scan = scan_index;
            thread_data[thread_index].end_scan = scan_index + 1;

            // Calculate port ranges
            thread_data[thread_index].start_port = current_start_port;
            thread_data[thread_index].end_port = thread_data[thread_index].start_port + ports_per_thread;

            // Add additional ports for first threads
            if (i < extra_ports) {
                thread_data[thread_index].end_port++;
            }

            // Update the start of the next range
            current_start_port = thread_data[thread_index].end_port;

            // printf("Thread %d: scans [", thread_index);
            // for (int scan_id = thread_data[thread_index].start_scan; scan_id < thread_data[thread_index].end_scan; scan_id++) {
            //     printf("%s", get_scan_name(options->tabscan[scan_id]));
            //     if (scan_id < thread_data[thread_index].end_scan - 1) {
            //         printf(", ");
            //     }
            // }
            // printf("], ports [%d, %d)\n", 
            //     thread_data[thread_index].start_port, 
            //     thread_data[thread_index].end_port);

            // Create the thread
            if (pthread_create(&threads[thread_index], NULL, threaded_scan, &thread_data[thread_index]) != 0) {
                perror("Failed to create thread");
                exit(1);
            }

            thread_index++;
        }
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
}

