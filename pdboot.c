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

__boot static 
void bootstrap(
    // r0-r3
    PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,
        
    // stack-allocated args
    SDFile* file
)
{
    char msg[8];
    msg[0] = 'H';
    msg[1] = 'e';
    msg[2] = 'l';
    msg[3] = 'l';
    msg[4] = 'o';
    msg[5] = '!';
    msg[6] = '\0';
    playdate->system->logToConsole(msg);
}

void _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg);
int eventHandlerShim(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    playdate->system->logToConsole(NAME_AND_VERSION "\n");
    playdate->system->logToConsole("PDBoot entrypoint: %p\n", &_entrypoint_);
    playdate->system->setUpdateCallback(update, NULL);
    
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
    
    // copy bootstrap to safe-execute region.
    // (It just so happens that the frame buffer itself is safe to execute from.)
    uint8_t* buff = playdate->graphics->getFrame();
    
    playdate->system->logToConsole("Copying shim to %p", buff);
    
    memcpy(buff, &__boot_start__, BOOT_SIZE);
    
    wait();
    
    int (*bootstrap_shim)(
        // r0-r3
        PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,
        
        // stack-allocated args
        SDFile* file
    ) = (void*)((uintptr_t)(void*)&bootstrap - (uintptr_t)(void*)&__boot_start__ + (uintptr_t)(void*)buff);
    
    // this MUST tail-call.
    return bootstrap_shim(
        playdate, event, arg, (void*)base_addr,
        
        file
    );
}

// very short entrypoint function that pre-empts the eventHandlerShim.
// This must be located at exactly the segment start, so that it aligns with the
// entrypoint in the pdb
__attribute__((section(".entry")))
__attribute__((naked))
void _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    asm volatile (
        "ldr r3, =eventHandlerShim\n\t"
        "bx r3\n\t"
    );
}

#endif