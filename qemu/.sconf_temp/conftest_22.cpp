
    #define _GNU_SOURCE
    #include <unistd.h>
    #include <fcntl.h>
    #include <limits.h>

    int main(void)
    {
        int len, fd;
        len = tee(STDIN_FILENO, STDOUT_FILENO, INT_MAX, SPLICE_F_NONBLOCK);
        splice(STDIN_FILENO, NULL, fd, NULL, len, SPLICE_F_MOVE);
        return 0;
    }
    