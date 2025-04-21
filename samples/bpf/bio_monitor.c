#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, long long);
} io_stats SEC(".maps");

SEC("tracepoint/block/block_bio_queue")
int trace_bio_queue(void *ctx)
{
    int key = 1;
    long long *value, initial = 1;
    
    value = bpf_map_lookup_elem(&io_stats, &key);
    if (value) {
        (*value)++;
    } else {
        bpf_map_update_elem(&io_stats, &key, &initial, 0);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
