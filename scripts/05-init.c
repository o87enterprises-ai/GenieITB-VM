/* Static /init for the minimal rootfs, so the guest needs no shell.
   -DTRIPWIRE sets the guest's denial limit. -DAGENT limits the guest to one agent, for
   one-VM-per-agent runs (/init-doc, /init-shell). */
#include <unistd.h>
#ifndef AGENT
#define AGENT (char *)0
#endif
int main(void) {
    execl("/05-supervisor", "/05-supervisor", TRIPWIRE, AGENT, (char *)0);
    return 127;
}
