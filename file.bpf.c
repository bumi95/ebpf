#include "bpf.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/security_file_open")
int BPF_PROG(handle_open, struct file *f)
{
    /* ring 버퍼로 task, 파일에 대한 정보를 담아 유저로 전송 */
}