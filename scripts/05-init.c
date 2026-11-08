/* Static /init for the minimal rootfs, so the guest needs no shell.
   Built twice: -DTRIPWIRE=\"4\" (/init) and -DTRIPWIRE=\"3\" (/init-trip). */
#include <unistd.h>
int main(void) {
    execl("/05-supervisor", "/05-supervisor", TRIPWIRE, (char *)0);
    return 127;
}
