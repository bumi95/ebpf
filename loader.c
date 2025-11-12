/* 로더 프로그램 */
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>

#include "loader.skel.h"

int g_loop = 0;

bool bump_memlock_rlimit()
{
    struct rlimit rlim_new = {
        .rlim_cur   = RLIM_INFINITY,
        .rlim_max   = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return false;
    }

    return true;
}

void sig_handler(int signo)
{
    g_loop = 1;
}

bool set_signal_handler()
{
    __sighandler_t handler = signal(SIGINT, sig_handler);
    if (handler == SIG_ERR) {
        perror("signal");
        return false;
    }

    handler = signal(SIGTERM, sig_handler);
    if (handler == SIG_ERR) {
        perror("signal");
        return false;
    }

    return 0;
}

int main()
{
    struct loader_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    if (!bump_memlock_rlimit()) {
        return -1;
    }

    if (!set_signal_handler()) {
        return -1;
    }

    skel = loader_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return -1;
    }

    skel->rodata->g_self_pid = getpid();

    err = loader_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skeleton: %d\n", -err);
        goto cleanup;
    }

    err = loader_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton: %d\n", -err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb))
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer (%d)\n", err);
        goto cleanup;
    }

    printf("successfully started! please press Ctrl+C to stop.\n");
    while (!g_loop) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            // Ctrl+C
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    loader_bpf__destroy(skel);
    return -err;
}