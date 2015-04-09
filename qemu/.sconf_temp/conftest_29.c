

#include <assert.h>

#ifdef __cplusplus
extern "C"
#endif
char fdatasync();

int main() {
#if defined (__stub_fdatasync) || defined (__stub___fdatasync)
  fail fail fail
#else
  fdatasync();
#endif

  return 0;
}
