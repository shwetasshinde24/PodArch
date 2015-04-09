
    #include <linux/kvm.h>
    #if !defined(KVM_API_VERSION) || KVM_API_VERSION < 12 || KVM_API_VERSION > 12
    #error Invalid KVM Version
    #endif
    int main() { return 0;}
    