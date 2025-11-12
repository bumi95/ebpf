#include "bpf.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/security_file_open")
int BPF_PROG(handle_open, struct file *f)
{
    if (is_skip_event()) {
        return 0;
    }

    struct bpf_event *e = alloc_event();
    if (!e) {
        bpf_printk("event alloc failed\n");
        return 0;
    }

    set_file_info(e, f);

    submit_event(e);

    return 0;
}
