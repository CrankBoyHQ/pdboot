#include <string.h>

#ifndef APPNAME
    #define APPNAME "app@.pdb"
#endif

#define NAME_AND_VERSION "PDBoot v1.0"
#define PDB_VERSION 1
#define PDB_MAGIC "\xAAPDBoot\x01"

#include "pd_api.h"

#define MEM_SIZE 16000000

// reserve space for loaded binary
__attribute__((section(".reserved")))
volatile char reserved[MEM_SIZE - HEAP_SIZE];

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

__boot static 
int bootstrap(
    // r0-r3
    PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,
        
    // stack-allocated args
    char* buff, size_t size, entrypoint_t entrypoint, wait_t wait
)
{
    char msg[9];
    
    void* dat = (void*)((uintptr_t)entrypoint & ~1);
    for (size_t i = 0; i < 8; ++i)
    {
        read_byte_to_msg(msg, dat + 0);
        read_byte_to_msg(msg+2, dat + 1);
        read_byte_to_msg(msg+4, dat + 2);
        read_byte_to_msg(msg+6, dat + 3);
        playdate->system->logToConsole(msg);
        dat += 4;
    }
    
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
    
    dat = (void*)((uintptr_t)entrypoint & ~1);
    for (size_t i = 0; i < 8; ++i)
    {
        read_byte_to_msg(msg, dat + 0);
        read_byte_to_msg(msg+2, dat + 1);
        read_byte_to_msg(msg+4, dat + 2);
        read_byte_to_msg(msg+6, dat + 3);
        playdate->system->logToConsole(msg);
        dat += 4;
    }
    wait();
    
    return entrypoint(playdate, event, arg);
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

int _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg);
int eventHandlerShim(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    if (arg >= 1)
    {
        // avoid using a string, since those don't seem to load correctly
        // in a .pdb
        char msg[4];
        msg[0] = '!';
        msg[1] = '\0';
        playdate->system->logToConsole(msg);
        return 0;
    }
    if (event != kEventInit) return 0;
    
    playdate->system->logToConsole(NAME_AND_VERSION "\n");
    playdate->system->logToConsole("PDBoot entrypoint: %p\n", &_entrypoint_);
    playdate->system->setUpdateCallback(update, NULL);
    wait();
    
    if (arg >= 1)
    {
        playdate->system->logToConsole("depth limit exceeded, so stopping things here.");
        return 0;
    }
    arg+=2;
    
    void* lr = __builtin_frame_address(0);
    if (event != kEventInit) return 0;
    
    uintptr_t base_addr = get_base_addr();
    
    playdate->system->logToConsole("LR: %p\nBase Address: %x\n", lr, base_addr);
    
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
    
    int (*bootstrap_shim)(
        // r0-r3
        PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,
        
        // stack-allocated args
        char* buff, size_t size, entrypoint_t entrypoint, wait_t wait
    ) = (void*)((uintptr_t)(void*)&bootstrap - (uintptr_t)(void*)&__boot_start__ + (uintptr_t)(void*)bs_region);
    
    // this MUST tail-call.
    return bootstrap_shim(
        playdate, event, arg, (void*)base_addr,
        buff, size, &_entrypoint_, (void*)((uintptr_t)(void*)&wait - (uintptr_t)(void*)&__boot_start__ + (uintptr_t)(void*)bs_region)
    );
}

// very short entrypoint function that pre-empts the eventHandlerShim.
// This must be located at exactly the segment start, so that it aligns with the
// entrypoint in the pdb
__attribute__((section(".entry")))
__attribute__((naked))
int _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    asm volatile (
        "cmp r2, #1"$
        "itt eq"$              // If-Then block (Thumb-2)
        "moveq r0, r2"$        // Conditional move
        "bxeq lr"$             // Conditional return
        "ldr r3, =eventHandlerShim"$
        "bx r3"$
    );
}

#endif