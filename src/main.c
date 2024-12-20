#include "../include/ft_nmap.h"

ScanOptions *global_options = NULL;

void print_starting_message() {
    time_t now;
    struct tm *local_time;
    char time_str[100];
    
    time(&now);
    local_time = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M %Z", local_time);
    printf("Starting ft_nmap at %s\n", time_str);
}

const char* get_scan_name(int scan_code) {
    switch (scan_code) {
        case SYN: return "SYN";
        case SCAN_NULL: return "NULL";
        case FIN: return "FIN";
        case XMAS: return "XMAS";
        case ACK: return "ACK";
        case UDP: return "UDP";
        default: return "UNKNOWN";
    }
}

void print_scan_types(ScanOptions *options) {
    printf("Selected scan types: ");
    for (int i = 0; i < options->scan_count; i++) {
        printf("%s", get_scan_name(options->tabscan[i]));
        if (i < options->scan_count - 1) {
            printf(", ");
        }
    }
    printf("\n");
}


int main(int ac, char **av) {
    ScanOptions options = {NULL, NULL, NULL, 0, 0, {0}, 0, 0, NULL, NULL, 0, NULL, NULL, NULL, 0, {0}, 0, 0, 0};
    global_options = &options;
    signal(SIGINT, signal_handler);
    struct timeval start, end;
    gettimeofday(&start, NULL);  // start time

    // Parsing args
    parse_arguments(ac, av, &options);

    if (options.flag_ports == 0) {
        for (int port = 1; port <= 1024; port++)
            options.portsTab[port - 1] = port;
        options.portsTabSize = 1024;
    }

    initialize_status(&options, options.scan_count, MAX_PORT);

    for(int i = 0; i < options.ip_count; i++){

        handle_ip_option_in_file(&i, &options);
        int use_loopback = strcmp(options.ip_address, "127.0.0.1") == 0;
        options.local_ip = get_local_ip(use_loopback, &options);
        options.local_interface = get_local_interface(use_loopback, &options);
        pcap_t *handle = init_pcap(options.local_interface);
        print_starting_message();
        if(options.speedup != 0)
                run_scans_by_techniques(&options);
        else
            tcp_scan_all_ports(&options);
        wait_for_responses(handle, &options);
        pcap_close(handle);
        // Show ports, excluding those in "CLOSED" state
        print_ports_excluding_state(&options, "CLOSED");
        printf("\n");
        reset_status(&options, options.scan_count, MAX_PORT);
    }

    cleanup_options(&options);
    gettimeofday(&end, NULL);  // end time
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

    // Show elapsed time
    if(options.ip_count == 0)
        options.ip_count++;
    printf("Nmap done: %d IP address (1 host up) scanned in %.2f seconds\n", options.ip_count, elapsed_time);

    return 0;
}