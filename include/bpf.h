#ifndef __BPF_H__
#define __BPF_H__

#include "map.h"
#include "common.h"
#include <bpf/bpf_core_read.h>

const volatile int g_self_pid = 0;

/* ring 버퍼 api 추가 */
bool is_skip_event(void)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    
    if (g_self_pid == pid) {
        return true;
    }

    return false;
}

struct bpf_event *alloc_event(void)
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
    e->uid = cred->uid.val;
    e->gid = cred->gid.val;
    e->euid = cred->euid.val;
    e->egid = cred->egid.val;
    e->cap_permitted = cred->cap_permitted.val;
    e->cap_effective = cred->cap_effective.val;

    struct file *f = BPF_CORE_READ(task, mm, exe_file);
    if (f) {
        struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
        struct qstr d_name = BPF_CORE_READ(d, d_name);
        bpf_probe_read_kernel(&e->comm, SIZE, d_name.name);
    }

    return e;
}

int set_file_info(struct bpf_event *e, struct file *f)
{
    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    struct qstr d_name = BPF_CORE_READ(d, d_name);
    bpf_probe_read_kernel(&e->filepath, SIZE, d_name.name);
    
    const struct cred *f_cred = BPF_CORE_READ(f, f_cred);

    e->f_uid = f_cred->uid.val;
    e->f_gid = f_cred->gid.val;
    e->f_euid = f_cred->euid.val;
    e->f_egid = f_cred->egid.val;
    e->f_cap_permitted = f_cred->cap_permitted.val;
    e->f_cap_effective = f_cred->cap_effective.val;

    return 0;
}

int submit_event(struct bpf_event *e)
{
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __BPF_H__ */
