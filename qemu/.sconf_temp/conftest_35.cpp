
    #define _GNU_SOURCE
    #include <unistd.h>
    #include <sys/syscall.h>
    #include <signal.h>
    int main(void) { return syscall(SYS_signalfd, -1, NULL, _NSIG / 8); }
    