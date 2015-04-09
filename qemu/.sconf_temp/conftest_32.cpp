
    #include <sys/ioctl.h>
    #include <linux/fs.h>
    #include <linux/fiemap.h>

    int main(void)
    {
        ioctl(0, FS_IOC_FIEMAP, 0);
        return 0;
    }
    