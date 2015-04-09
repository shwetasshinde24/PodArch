
    #define _GNU_SOURCE
    #include <sys/socket.h>
    #include <stddef.h>

    int main(void)
    {
        accept4(0, NULL, NULL, SOCK_CLOEXEC);
        return 0;
    }
    