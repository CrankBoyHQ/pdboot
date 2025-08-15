#include <string.h>

#include "pdboot.h"

#ifndef APPNAME
    #define APPNAME "app@.pdb"
#endif

#define NAME_AND_VERSION "PDBoot v1.0"
#define PDB_VERSION_MAJOR 1
#define PDB_VERSION_MINOR 0

#include "pd_api.h"

#define MEM_SIZE 16000000

#ifndef TARGET_SIMULATOR
// reserve space for loaded binary
__attribute__((section(".reserved")))
volatile char reserved[MEM_SIZE - HEAP_SIZE];
#endif

int update(void* ud)
{
    return 0;
}

int eventHandler(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    playdate->system->setUpdateCallback(update, NULL);
    playdate->system->logToConsole("\n[ERROR] PDBoot only works on actual hardware.\n");
    return 0;
}

#ifndef TARGET_SIMULATOR

#define $ "\n\t"

#define __boot __attribute__((short_call)) __attribute__((section(".boot")))

extern char __text_start__, __boot_start__, __data_end__;

#define BOOT_SIZE ((uintptr_t)(&__data_end__ - &__boot_start__))

__attribute__((noinline)) static
uintptr_t get_base_addr(void) {
    return ((uintptr_t)(void*)&get_base_addr) & 0xFF000000;
}

#define REV_A 0
#define REV_B 1
#define REV_UNKNOWN 2

const char* REV_CHAR = "ABCDEF";

static int get_rev(uintptr_t base_addr)
{
    if (base_addr == 0x60000000)
    {
        return REV_A;
    }
    else if (base_addr == 0x90000000)
    {
        return REV_B;
    }
    else
    {
        return REV_UNKNOWN;
    }
}

static bool select_app(char rev_char)
{
    char* s = strchr((char*)APPNAME, '@');
    if (!s) return false;

    *s = rev_char;

    return true;
}

__boot static
void wait(void)
{
    // wait a bit to flush the console
    for (int i = 0; i < 1600000; ++i)
    {
        asm ("nop");
    }
}

typedef int (*entrypoint_t)(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg);
typedef void (*wait_t)(void);

__boot static
void read_byte_to_msg(char* msg, void* b)
{
    uint8_t v = *(uint8_t*)b;
    if ((v&0xF) < 10) msg[1] = '0' + (v&0xF);
    else msg[1] = 'A' + (v&0xF) - 10;

    v >>= 4;

    if (v < 10) msg[0] = '0' + v;
    else msg[0] = 'A' + v - 10;
    msg[2] = 0;
}

__boot __attribute__((naked))
void hard_jump_to_entrypoint(
    // r0-r3
    PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* regs
)
{
    __asm__ volatile (
        "ldr r4, [r3], #4"$
        "ldr r5, [r3], #4"$
        "ldr r6, [r3], #4"$
        "ldr r7, [r3], #4"$
        "ldr r8, [r3], #4"$
        "ldr r9, [r3], #4"$
        "ldr r10, [r3], #4"$
        "ldr r11, [r3], #4"$
        "ldr r12, [r3], #4"$
        "ldr lr, [r3], #4"$
        "ldr sp, [r3], #4"$
        "ldr r3, [r3]"$
        "bx     r3"$ // jump to entrypoint
    );
}

__boot static
void bootstrap(
    // r0-r3
    PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,

    // stack-allocated args
    char* buff, size_t size, wait_t wait,
    pdboot_data_t* data
)
{
    char msg[9];

    msg[0] = 'H';
    msg[1] = 'e';
    msg[2] = 'l';
    msg[3] = 'l';
    msg[4] = 'o';
    msg[5] = '!';
    msg[6] = '\0';
    playdate->system->logToConsole(msg);
    wait();

    // copy pdb into memory
    for (size_t i = 0; i < size; ++i)
    {
        ((char*)base_addr)[i] = buff[i];
    }

    // zero bss
    for (size_t i = size; i < MEM_SIZE - HEAP_SIZE; ++i)
    {
        ((char*)base_addr)[i] = 0;
    }

    playdate->system->logToConsole(msg);
    wait();

    playdate->system->realloc(buff, 0);
    playdate->system->clearICache();

    playdate->system->logToConsole(msg);
    wait();

    hard_jump_to_entrypoint(playdate, event, arg, data->regs);
}

static
char* read_entire_file(PlaydateAPI* playdate, SDFile* file, size_t* o_size, size_t max_size)
{
    char* dat;
    char* out;
    int size;
    if (!file)
        return NULL;

    if (playdate->file->seek(file, 0, SEEK_END) < 0)
        goto fail;

    size = playdate->file->tell(file);
    if (o_size)
        *o_size = size;
    if (size < 0 || size > max_size)
        goto fail;

    if (playdate->file->seek(file, 0, SEEK_SET))
        goto fail;

    dat = playdate->system->realloc(NULL, size + 1);
    if (!dat)
        goto fail;

    out = dat;
    while (size > 0)
    {
        int read = playdate->file->read(file, out, size);
        if (read <= 0)
            goto fail_free_dat;

        size -= read;
        out += read;
    }

    // ensure terminal 0
    *out = 0;

    playdate->file->close(file);
    return dat;

fail_free_dat:
    playdate->system->realloc(dat, 0);

fail:
    playdate->file->close(file);
    return NULL;
}

// regs r4-r12
static void* regs[11];

int _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg);
int pdboot_main(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    void* fp = regs[8];
    void* lr = regs[9];
    void* sp = regs[10];

    if (event != kEventInit) return 0;

    playdate->system->logToConsole(NAME_AND_VERSION "\n");
    playdate->system->logToConsole("PDBoot entrypoint: %p\n", &_entrypoint_);

    wait();

    if (arg >= 2)
    {
        playdate->system->logToConsole("depth limit exceeded, so stopping things here.");
        return 0;
    }
    arg++;

    if (event != kEventInit) return 0;

    uintptr_t base_addr = get_base_addr();

    playdate->system->logToConsole("LR: %p\nSP: %p\nFP: %p\nBase Address: %x\n", lr, sp, fp, base_addr);

    int rev = get_rev(base_addr);

    if (rev == REV_UNKNOWN)
    {
        playdate->system->error("Unrecognized hardware. PDBoot only supports Rev A and Rev B devices.");
        return 0;
    }

    char rev_char = REV_CHAR[rev];

    playdate->system->logToConsole("Rev %c detected", rev_char);

    if (!select_app(rev_char))
    {
        playdate->system->error("Failed to find wildcard '@' in appname \"%s\"", APPNAME);
        return 0;
    }

    // copy bootstrap to safe-execute region.
    // (It just so happens that the frame buffer itself is safe to execute from.)
    uint8_t* bs_region = playdate->graphics->getFrame();

    pdboot_data_t* data = (void*)bs_region;
    bs_region += sizeof(*data);
    strcpy(data->magic, PDBOOT_MAGIC);
    strcpy(data->name_and_version, NAME_AND_VERSION);
    data->version_major = PDB_VERSION_MAJOR;
    data->version_minor = PDB_VERSION_MINOR;

    memcpy(data->regs, regs, sizeof(data->regs));
    data->entrypoint = &_entrypoint_;

    // align % 2
    while ((uintptr_t)bs_region % 2) ++bs_region;

    playdate->system->logToConsole("Copying shim to %p", bs_region);

    memcpy(bs_region, &__boot_start__, BOOT_SIZE);

    wait();

    // paranoia: force compiler to include this
    reserved[sizeof(reserved) - 1] = 1;

    SDFile* file = playdate->file->open(APPNAME, kFileRead);
    if (file)
    {
        playdate->system->logToConsole("Launching %s from pdx...", APPNAME);
    }
    else
    {
        SDFile* file = playdate->file->open(APPNAME, kFileReadData);
        if (file)
        {
            playdate->system->logToConsole("Launching %s from data...", APPNAME);
        }
        else
        {
            playdate->system->error("File \"%s\" not present in pdx nor data", APPNAME);
            return 0;
        }
    }

    // copy file contents to buffer
    size_t size = 0;
    char* buff = read_entire_file(playdate, file, &size, MEM_SIZE - HEAP_SIZE);

    if (!buff || !size)
    {
        if (size > MEM_SIZE - HEAP_SIZE)
        {
            playdate->system->error("[Error] pdb file exceeds maximum size (0x%06x > 0x%06x)", size, MEM_SIZE - HEAP_SIZE);
        }
        playdate->system->error("[Error] unable to read pdb file.");
        return 0;
    }

    void (*bootstrap_shim)(
        // r0-r3
        PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,

        // stack-allocated args
        char* buff, size_t size, wait_t wait,
        void* data
    ) = (void*)((uintptr_t)(void*)&bootstrap - (uintptr_t)(void*)&__boot_start__ + (uintptr_t)(void*)bs_region);


    // (note: doesn't return here)
    bootstrap_shim(
        playdate, event, arg, (void*)base_addr,
        buff, size, (void*)((uintptr_t)(void*)&wait - (uintptr_t)(void*)&__boot_start__ + (uintptr_t)(void*)bs_region),
        data
    );
    return 0;
}

// very short entrypoint function that pre-empts pdboot_main
// This must be located at exactly the segment start, so that it aligns with the
// entrypoint in the pdb
__attribute__((section(".entry")))
__attribute__((naked))
int _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    asm volatile (
        "ldr r3, =regs"$
        "str r4, [r3], #4"$
        "str r5, [r3], #4"$
        "str r6, [r3], #4"$
        "str r7, [r3], #4"$
        "str r8, [r3], #4"$
        "str r9, [r3], #4"$
        "str r10, [r3], #4"$
        "str r11, [r3], #4"$
        "str r12, [r3], #4"$
        "str lr, [r3], #4"$
        "str sp, [r3], #4"$
        "ldr r3, =pdboot_main"$
        "bx r3"$
    );
}

#endif
