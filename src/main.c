#include "../include/ft_nmap.h"

void *thread_scan(void *arg) {
    ScanTask *task = (ScanTask *)arg;

    // Scanner les ports attribués à ce thread
    for (int i = task->start_index; i <= task->end_index; i++) {
        printf("Scanning IP: %s, Port: %d, Scan Type: %s\n", task->ip, task->ports[i], task->scan_type);
    }
    pthread_exit(NULL);
}

int main(int ac, char **av)
{
    ScanOptions options = {NULL, NULL, 0, NULL, {0}, 0, NULL, NULL, 0};

    parse_arguments(ac, av, &options);

    printf("-----------COMMAND--------------\n");
    printf("IP Address: %s\n", options.ip_address);
    printf("Ports: %s\n", options.ports);
    printf("File: %s\n", options.file);
    for (int j = 0; j < options.ip_count; j++)
        printf("   Stored IP: %s\n", options.ip_list[j]);
    printf("Speedup: %d\n", options.speedup);
    printf("Scan Type: %s\n", options.scan_type);
    printf("---------------------------------\n");

    printf("Ports stockés sans doublons :\n");
    for (int j = 0; j < options.portsTabSize; j++) {
        printf("Port: %d\n", options.portsTab[j]);
    }

    pthread_t threads[options.speedup];
    ScanTask tasks[options.speedup];

    int ports_per_thread = options.portsTabSize / options.speedup;
    int remaining_ports = options.portsTabSize % options.speedup;
    int current_index = 0;

    for (int i = 0; i < options.speedup; i++) {
        tasks[i].ip = options.ip_address;
        tasks[i].ports = options.portsTab;
        tasks[i].scan_type = options.scan_type;
        tasks[i].start_index = current_index;
        tasks[i].end_index = current_index + ports_per_thread - 1;

        // Répartir les ports restants
        if (remaining_ports > 0) {
            tasks[i].end_index++;
            remaining_ports--;
        }

        // Créer le thread pour chaque tâche
        if (pthread_create(&threads[i], NULL, thread_scan, &tasks[i]) != 0) {
            perror("Failed to create thread");
            return 1;
        }

        current_index = tasks[i].end_index + 1;
    }

    // Attendre la fin de tous les threads
    for (int i = 0; i < options.speedup; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int j = 0; j < options.ip_count; j++)
        free(options.ip_list[j]);
    free(options.ip_list);
    return 0;
}