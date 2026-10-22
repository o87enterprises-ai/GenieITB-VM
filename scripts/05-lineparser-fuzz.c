/* 05-lineparser-fuzz.c — fuzz harness for the guest supervisor's line
 * assembler (review T9). Mirrors the exact buffer handling in
 * 05-supervisor.c main loop: a fixed LINE_MAX buffer, append up to
 * sizeof-1, NUL-terminate, split on '\n' with memchr, consume with
 * memmove. The goal is to find buffer-handling bugs (OOB read/write,
 * off-by-one) in that state machine — build with ASan.
 *
 * Fuzzing OUR OWN parser to harden it; not an attack on anything.
 *
 * AFL build:   afl-gcc -O2 -fsanitize=address -o /tmp/05-lineparser-fuzz \
 *                  scripts/05-lineparser-fuzz.c
 * AFL run:     afl-fuzz -i corpus -o findings -- /tmp/05-lineparser-fuzz
 * Standalone:  /tmp/05-lineparser-fuzz < somefile   (replays once)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define LINE_MAX 1024

static volatile unsigned long g_sink;   /* defeat dead-store elimination */

/* Replay `in`/`n` as a sequence of reads of `chunk` bytes each, feeding the
   same buffer state machine 05-supervisor.c uses. */
static void process_stream(const uint8_t *in, size_t n, size_t chunk) {
    char   buf[LINE_MAX];
    size_t len = 0;
    size_t off = 0;
    if (chunk == 0) chunk = 1;

    while (off < n) {
        size_t cap = sizeof buf - len - 1;      /* same as supervisor.c */
        if (cap == 0) {                          /* line too long: fd closed */
            len = 0;                             /* mimic agent-gone reset */
            continue;
        }
        size_t want = n - off;
        if (want > chunk) want = chunk;
        if (want > cap)   want = cap;
        memcpy(buf + len, in + off, want);
        off += want;
        len += want;
        buf[len] = 0;

        char *nl;
        while ((nl = memchr(buf, '\n', len))) {
            *nl = 0;
            g_sink += (unsigned long)strlen(buf);          /* "handle" line */
            size_t consumed = (size_t)(nl - buf) + 1;
            memmove(buf, nl + 1, len - consumed);
            len -= consumed;
            buf[len] = 0;
        }
    }
}

int main(void) {
    static uint8_t in[1 << 20];
    size_t n = 0, r;
    while (n < sizeof in && (r = fread(in + n, 1, sizeof in - n, stdin)) > 0)
        n += r;

    /* Replay under several chunk sizes so boundary alignments vary. */
    static const size_t chunks[] = { 1, 2, 3, 7, 64, 1023, 4096 };
    for (size_t i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
        process_stream(in, n, chunks[i]);

    return 0;
}
