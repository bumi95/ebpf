#ifndef __COMMON_H__
#define __COMMON_H__

#define SIZE    4096

struct bpf_event {
    int pid;
    /* 프로세스(task)의 cred 정보 */
    unsigned int uid;
    unsigned int gid;
    unsigned int euid;
    unsigned int egid;
    unsigned long long cap_permitted;
    unsigned long long cap_effective;
    /* file이 갖고 있는 cred 정보 */
    unsigned int f_uid;
    unsigned int f_gid;
    unsigned int f_euid;
    unsigned int f_egid;
    unsigned long long f_cap_permitted;
    unsigned long long f_cap_effective;
    char comm[SIZE];
    char filepath[SIZE];
};

#endif /* __COMMON_H__ */
