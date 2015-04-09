
    #define _GNU_SOURCE
    #include <unistd.h>
    #include <fcntl.h>

    int main(void)
    {
        int pipefd[2];
        pipe2(pipefd, O_CLOEXEC);
        return 0;
    }
    