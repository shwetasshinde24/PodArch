 // test-cpuid.c
 // compile with: cc -m32 testcpuid.c -o test-cpuid

 #include <stdio.h>

 int main(int argc, char **argv)
 {
        unsigned int eax, ebx, ecx, edx;
        __asm__ __volatile__ ("movl $1, %%eax\n\t"
                              "cpuid"
                              : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx));
        if (edx & (1 << 10)) {
                printf("PodArch\n");
        } else {
                printf("Not PodArch\n");
        }
        return 0;
 }
