#define SIZE    256

struct event {
    int pid;
    /* 프로세스(task)의 cred 정보 */
    /* file이 갖고 있는 cred 정보 */
    char comm[16];
    char filepath[SIZE];
};