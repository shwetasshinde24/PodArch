
    #define _ATFILE_SOURCE
    #include <stddef.h>
    #include <fcntl.h>

    int main(void)
    {
        utimensat(AT_FDCWD, "foo", NULL, 0);
        futimens(0, NULL);
        return 0;
    }
    