
    #include <sys/types.h>
    #include <sys/mman.h>
    #include <stddef.h>
    int main(void) { return madvise(NULL, 0, MADV_DONTNEED); }
    