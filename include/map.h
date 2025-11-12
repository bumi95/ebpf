#ifndef __MAP_H__
#define __MAP_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024); // 16MB
} rb SEC(".maps");

#endif /* __MAP_H__ */
