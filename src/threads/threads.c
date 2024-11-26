#include "threads.h"
#include "ft_nmap.h"

void *thread_worker(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    ScanOptions *options = data->options;

    // Répartir les ports en fonction de l'ID du thread
    for (int i = 0; i < options->portsTabSize; i++) {
        if (i % data->total_threads == data->thread_id) {
            int port = options->portsTab[i];
            printf("Thread %d scanning port %d\n", data->thread_id, port);

            // Appeler la fonction de scan pour ce port
            // (fonction à adapter si besoin)
            // send_packet(/* Paramètres du scan : socket, options, port, etc. */);
        }
    }

    pthread_exit(NULL);
}
