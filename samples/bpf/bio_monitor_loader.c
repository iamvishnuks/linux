#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int map_fd;
    int opt, run_time = 30;
    
    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "ht:")) != -1) {
        switch (opt) {
        case 'h':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("  -h         Show this help\n");
            printf("  -t SECONDS Run for SECONDS seconds (default: 30)\n");
            return 0;
        case 't':
            run_time = atoi(optarg);
            if (run_time <= 0) {
                fprintf(stderr, "Invalid run time\n");
                return 1;
            }
            break;
        default:
            fprintf(stderr, "Usage: %s [-t seconds]\n", argv[0]);
            return 1;
        }
    }
    
    /* Set up signal handling */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load BPF program - simpler approach */
    obj = bpf_object__open("bio_monitor.o");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));
        return 1;
    }

    /* Load the BPF program */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Find maps */
    map_fd = bpf_object__find_map_fd_by_name(obj, "io_stats");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find io_stats map: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Find and attach the program */
    prog = bpf_object__find_program_by_name(obj, "trace_bio_queue");
    if (!prog) {
        fprintf(stderr, "Failed to find program: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Attach to tracepoint */
    link = bpf_program__attach_tracepoint(prog, "block", "block_bio_queue");
    if (!link) {
        fprintf(stderr, "Failed to attach tracepoint: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("BPF program loaded and attached successfully\n");
    printf("Tracking block I/O operations for %d seconds...\n", run_time);
    printf("Press Ctrl+C to stop\n");

    /* Run for specified time or until interrupted */
    int elapsed = 0;
    while (!exiting && elapsed < run_time) {
        sleep(1);
        elapsed++;
        
        /* Print a status indicator */
        printf(".");
        fflush(stdout);

        /* Display current stats every 5 seconds */
        if (elapsed % 5 == 0) {
            int key = 1;
            long long value;
            
            if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
                printf(" %lld operations\n", value);
            } else {
                printf(" (no data)\n");
            }
        }
    }

    printf("\nFinal I/O Statistics:\n");
    
    /* Read and display counts */
    int key = 1;
    long long value;
    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("Block I/O operations: %lld\n", value);
    } else {
        printf("No data collected\n");
    }

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
