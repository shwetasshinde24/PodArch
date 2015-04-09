
    #include <sched.h>
    #include <linux/futex.h>
    void foo() {
    #if !defined(CLONE_SETTLS) || !defined(FUTEX_WAIT)
    #error bork
    #endif
    }
    