/*
 * vuln3.c  -  Deliberately vulnerable training target, v3 (x86_64).
 *
 * Three-bug CHAIN. Each bug has exactly one job:
 *   1. Use-after-free (read) -> leaks a libc pointer   (defeats ASLR)
 *   2. Format string         -> leaks the stack canary (defeats the canary)
 *   3. Stack buffer overflow -> ret2libc ROP           (defeats NX)
 *
 * Stage 3 needs BOTH leaks: the binary imports no system() and holds no
 * "/bin/sh" string, so there is no ret2plt shortcut. The only path to a
 * shell is system() computed from the leaked libc base, with the leaked
 * canary replanted. That is what forces bugs 1 and 2 to feed bug 3.
 *
 * Mitigations ON: NX, stack canary. OFF/weak on purpose: no PIE (fixed
 * gadget), partial RELRO (keeps the RELRO discussion live). Run with ASLR on.
 *
 * This is a target, not an exploit.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOT 16

/*
 * 0x420 request -> 0x430 chunk, above the 0x410 tcache ceiling, so a freed
 * note skips tcache and lands in the unsorted bin. A lone unsorted chunk's
 * fd/bk point into main_arena (inside libc) -> the UAF read leaks libc.
 */
static char *notes[NSLOT];

/*
 * Guaranteed `pop rdi ; ret`. Fixed address (no PIE). Never called.
 */
__attribute__((used))
void gadget_farm(void) {
    __asm__ __volatile__("pop %rdi\n\tret\n\t");
}

static int read_int(void) {
    char b[16];
    if (!fgets(b, sizeof b, stdin)) exit(0);
    return atoi(b);
}

static void do_alloc(void) {
    printf("slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOT) return;
    notes[i] = malloc(0x420);
    if (!notes[i]) return;
    printf("data: ");
    read(0, notes[i], 0x420);
}

static void do_free(void) {
    printf("slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOT) return;
    free(notes[i]);        /* BUG 1: dangling, notes[i] not cleared */
    /* notes[i] = NULL;  <- the missing fix */
}

/* UAF read: on a freed note this prints the chunk's fd/bk = libc leak. */
static void do_show(void) {
    printf("slot: ");
    int i = read_int();
    if (i < 0 || i >= NSLOT || !notes[i]) return;
    write(1, notes[i], 16);
}

/* BUG 2: user input used as the format string -> leak the canary with %N$p. */
static void do_echo(void) {
    char line[128];
    printf("msg: ");
    ssize_t n = read(0, line, sizeof line - 1);
    if (n <= 0) return;
    line[n] = 0;
    printf(line);
    putchar('\n');
}

/* BUG 3: 64-byte buffer, 256-byte read. Canary guards the frame. */
static void do_feedback(void) {
    char buf[64];
    puts("feedback:");
    read(0, buf, 256);
    printf("thanks, %s\n", buf);
}

static void menu(void) {
    puts("");
    puts("1)alloc 2)free 3)show 4)echo 5)feedback 0)quit");
    printf("> ");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    for (;;) {
        menu();
        switch (read_int()) {
            case 1: do_alloc();    break;
            case 2: do_free();     break;
            case 3: do_show();     break;
            case 4: do_echo();     break;
            case 5: do_feedback(); break;
            case 0: return 0;
            default: puts("?");
        }
    }
}
