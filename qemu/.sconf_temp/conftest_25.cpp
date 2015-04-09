
    #include <unistd.h>
    int main(void)
    {
        dup3(0, 0, 0);
        return 0;
    }
    