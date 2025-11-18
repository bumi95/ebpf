#ifndef __BPF_H__
#define __BPF_H__

#include "map.h"
#include "common.h"
#include <bpf/bpf_core_read.h>
#include "path_buf.h"

const volatile int g_self_pid = 0;

struct path_buf {
    char buf[4096];
};

void *get_buf(void)
{
    u32 key = bpf_get_smp_processor_id();
    struct path_buf *pb = bpf_map_lookup_elem(&bufs, &key);
    if (!pb) {
        bpf_printk("path_buf map lookup failed\n");
        return NULL;
    }

    return (void *)pb->buf;
}

/* ring 버퍼 api 추가 */
bool is_skip_event(void)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    
    if (g_self_pid == pid) {
        return true;
    }

    return false;
}

static __always_inline struct bpf_event *alloc_event(void)
{
    struct bpf_event *e = NULL;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e = bpf_ringbuf_reserve(&rb, sizeof(struct bpf_event), 0);
    if (!e) {
        bpf_printk("ringbuf reserve failed\n");
        return NULL;
    }

    const struct cred *cred = BPF_CORE_READ(task, cred);

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = BPF_CORE_READ(cred, uid.val);
    e->gid = BPF_CORE_READ(cred, gid.val);
    e->euid = BPF_CORE_READ(cred, euid.val);
    e->egid = BPF_CORE_READ(cred, egid.val);
    e->cap_permitted = BPF_CORE_READ(cred, cap_permitted.val);
    e->cap_effective = BPF_CORE_READ(cred, cap_effective.val);

    struct file *f = BPF_CORE_READ(task, mm, exe_file);
    if (f) {
        void *buf = get_buf();
        if (buf) {
            struct path f_path = BPF_CORE_READ(f, f_path);
            void *file_name = get_path_buf(&f_path, buf);
            bpf_probe_read_kernel(&e->comm, SIZE, file_name);
        }
    }

    return e;
}

static int set_file_info(struct bpf_event *e, struct file *f)
{
    struct path f_path = BPF_CORE_READ(f, f_path);
    void *buf = get_buf();
    if (!buf)
        return -1;
    
    void *file_name = get_path_buf(&f_path, buf);
    bpf_probe_read_kernel(&e->filepath, SIZE, file_name);
    
    const struct cred *f_cred = BPF_CORE_READ(f, f_cred);

    e->f_uid = BPF_CORE_READ(f_cred, uid.val);
    e->f_gid = BPF_CORE_READ(f_cred, gid.val);
    e->f_euid = BPF_CORE_READ(f_cred, euid.val);
    e->f_egid = BPF_CORE_READ(f_cred, egid.val);
    e->f_cap_permitted = BPF_CORE_READ(f_cred, cap_permitted.val);
    e->f_cap_effective = BPF_CORE_READ(f_cred, cap_effective.val);

    return 0;
}

int submit_event(struct bpf_event *e)
{
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __BPF_H__ */
