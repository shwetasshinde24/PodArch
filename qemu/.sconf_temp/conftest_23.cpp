
    #include <sys/eventfd.h>
    int main(void)
    {
        int efd = eventfd(0, 0);
        return 0;
    }
    