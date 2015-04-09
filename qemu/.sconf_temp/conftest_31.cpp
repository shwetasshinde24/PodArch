
    #include <fcntl.h>

    int main(void)
    {
        sync_file_range(0, 0, 0, 0);
        return 0;
    }
    