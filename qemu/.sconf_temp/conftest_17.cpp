
    #define _ATFILE_SOURCE
    #include <sys/types.h>
    #include <fcntl.h>
    #include <unistd.h>

    int
    main(void)
    {
        /* try to unlink nonexisting file */
        return (unlinkat(AT_FDCWD, "nonexistent_file", 0));
    }
    