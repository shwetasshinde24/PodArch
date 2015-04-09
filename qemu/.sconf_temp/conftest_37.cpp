
    #include <sys/mman.h>
    #include <stddef.h>
    int main(void) { return posix_madvise(NULL, 0, POSIX_MADV_DONTNEED); }
    