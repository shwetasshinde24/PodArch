
    #include <sys/inotify.h>

    int
    main(void)
    {
        /* try to start inotify */
        return inotify_init1(0);
    }
    