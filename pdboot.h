#ifndef _PDBOOT_H
#define _PDBOOT_H

#define PDBOOT_MAGIC "\xAAPDBoot\x01"

typedef struct pdboot_data
{
    char magic[8];

    char name_and_version[32];

    int version_major;
    int version_minor;

    char reserved[32];

    void* regs[11];
    void* entrypoint;
} pdboot_data_t;

// provided by setup.c in Playdate SDK
extern int eventHandlerShim(PlaydateAPI* p, PDSystemEvent e, uint32_t a);

#ifdef PDBOOT_MAIN
#ifndef TARGET_SIMULATOR
// short trampoline that jumps to the real entrypoint
__attribute__((section(".entry")))
__attribute__((naked))
int _entrypoint_(PlaydateAPI* p, PDSystemEvent e, uint32_t a)
{
    __asm__ volatile (
        "ldr r3, =eventHandlerShim\n\t"
        "bx r3\n\t"
    );
}
#endif
#endif

#endif /* _PDBOOT_H */
