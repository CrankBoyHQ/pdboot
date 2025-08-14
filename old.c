#ifndef APPNAME
    #define APPNAME "app.pdb"
#endif

#define NAME_AND_VERSION "PDBoot v1.0"
#define PDB_VERSION 1
#define PDB_MAGIC "\xAAPDBoot\x01"

#include "pd_api.h"

#define MEM_SIZE 16000000

__attribute__((section(".reserved")))
volatile char reserved[MEM_SIZE - HEAP_SIZE];

int update(void* ud)
{
    return 0;
}

int eventHandler(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    playdate->system->setUpdateCallback(update, NULL);
    printf("PDBoot only works on actual hardware.\n");
    return 0;
}


#ifndef TARGET_SIMULATOR

// force relative jumping/calling
#define __pdbcall __attribute__((short_call))

extern char __text_start__, __boot_start__, __data_end__;

#define SEGMENT_START (((uintptr_t)&__text_start__) & 0xFF000000)

#define BOOT_SIZE ((uintptr_t)(&__data_end__ - &__boot_start__))

__attribute__((section(".boot")))
__attribute__((naked))
void enter(void)
{
    #define $ "\n\t"
    __asm volatile (
    "push {lr, r0-r9}"$
        "ldr r4, [sp, #44]"$ // msg
        "ldr r5, [sp, #48]"$ // segment start
        "ldr r6, [sp, #52]"$ // pdb
        "ldr r7, [sp, #56]"$ // len
        "ldr r8, [sp, #60]"$ // realloc
        "ldr r9, [sp, #64]"$ // clearICache
        
        "mov r0, r6"$
        
    "loop_start:"$
        "cmp     r7, #0"$
        "beq     loop_end"$

        "ldrb    r1, [r6], #1"$ // Load byte from [r6++]
        "strb    r1, [r5], #1"$ // Store byte to [r5++]
        
        "subs    r7, r7, #1"$ // r7--
        "b       loop_start"$

    "loop_end:"$
    
        // FIXME: why does this crash?
        // free pdb
        //"mov r1, #0"$
        //"blx r8"$
        
        // clear icache
        "blx r9"$
        
        // print message
        "mov r0, r4"$
        "blx r3"$
        
        // wait
        //"ldr r0, [sp, #68]"$
        //"blx r0"$
        
    "pop {lr, r0-r9}"$
    
    "ldr r3, [sp, #4]"$ // pdb
    "orr r3, r3, #1"$
    "bx r3"$
    );
    #undef $
}

__pdbcall
static void wait(void)
{
    // wait a bit to flush the console
    for (int i = 0; i < 1600000; ++i)
    {
        asm ("nop");
    }
}

__pdbcall
static void saferead(PlaydateAPI* playdate, SDFile* file, void* _buff, int len)
{
    char* buff = _buff;
    if (len == 0) return;
    
    while (len > 0)
    {
        int read = playdate->file->read(file, buff, len);
        
        if (read <= 0)
        {
            playdate->system->error("Failed to read %d bytes from " APPNAME, len);
        }
        else
        {
            len -= read;
            buff += read;
        }
    }
}

static int bootstrap(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    void* lr = __builtin_frame_address(0);
    playdate->system->logToConsole("Entered bootstrap.\n");
    playdate->system->logToConsole("Bootstrap, LR: %p\nBootstrap, Segment Start: %x\n", lr, SEGMENT_START);
    
    const char* string = "This string is located at %p";
    
    playdate->system->logToConsole(
        string, string
    );
        
    wait();
    
    int (*targetEntrypoint)(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg) = (void*)(SEGMENT_START | 1);
    
    char bbuff[256];
    
    SDFile* file = playdate->file->open(APPNAME, kFileReadData);
    if (!file) file = playdate->file->open(APPNAME, kFileRead);
    
    if (!file)
    {
        playdate->system->error("Failed to open " APPNAME);
        return 0;
    }
    
    saferead(playdate, file, bbuff, strlen(PDB_MAGIC));
    if (strncmp(bbuff, PDB_MAGIC, strlen(PDB_MAGIC)))
    {
        playdate->system->error(APPNAME " is not in PDB format.");
    }
    
    uint32_t version;
    saferead(playdate, file, &version, sizeof(version));
    if (version != PDB_VERSION)
    {
        playdate->system->error(APPNAME " is a version %d PDBoot file, but this is PDBoot version %d. Please install another .pdb or else replace PDBoot (pdex.elf)", version, PDB_VERSION);
    }
    
    uint32_t data_len;
    saferead(playdate, file, &data_len, sizeof(data_len));
    
    playdate->system->logToConsole(
        APPNAME " is %u bytes of text + data", data_len
    );
    
    char* data = playdate->system->realloc(NULL, data_len);
    
    if (!data)
    {
        playdate->system->error("Unable to allocate room to copy " APPNAME " to.");
        return 0;
    }
    
    // read file in 256-byte chunks
    {
        unsigned len = data_len;
        char* _data = data;
        while (len > 0)
        {
            int to_read = len;
            if (to_read >= sizeof(bbuff)) to_read = sizeof(bbuff);
            
            saferead(playdate, file, _data, to_read);
            len -= to_read;
            _data += to_read;
        }
    }
    
    playdate->system->logToConsole(
        "Copied %u bytes to flash", data_len
    );
    
    while (true)
    {
        char section;
        saferead(playdate, file, &section, sizeof(section));
        switch(section)
        {
        case 0:
            goto done;
        case 2:
            {
                uint32_t count;
                saferead(playdate, file, &count, sizeof(count));
                
                playdate->system->logToConsole(
                    "Applying %u relocations...", count
                );
                
                for (unsigned i = 0; i < count; ++i)
                {
                    uint32_t reloc_addr;
                    saferead(playdate, file, &reloc_addr, sizeof(reloc_addr));
                    
                    uint32_t* reloc = (void*)(data + reloc_addr);
                    
                    *reloc += SEGMENT_START;
                }
            }
            break;
        default:
            playdate->system->error("Unknown section type %d", (int)section);
            break;
        }
    }
done:
    
    playdate->file->close(file);
    
    // copy `enter` to stack
    char _buff[BOOT_SIZE + 1];
    char* buff = ((uintptr_t)&_buff % 2)
        ? &_buff[1]
        : &_buff[0];
    
    // wait a bit to flush the console
    wait();
    
    memcpy(buff, &__boot_start__, BOOT_SIZE);
    
    int (*stack_enter)(
        // r0-r3
        PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* fn_log,
        
        // stack-allocated args
        const char* msg, void* segment_start, void* pdb, size_t len, void* fn_realloc, void* fn_clearICache,
        void* wait
    ) = (void*)((uintptr_t)(void*)&enter - (uintptr_t)(void*)&__boot_start__ + (uintptr_t)(void*)buff);
    
    playdate->system->logToConsole("Enter: %p", stack_enter);
    
    // wait a bit to flush the console
    wait();
    
    return stack_enter(playdate, event, arg, playdate->system->logToConsole, "---- Entering " APPNAME " ----", (void*)SEGMENT_START, data, data_len, playdate->system->realloc, playdate->system->clearICache, wait);
}

int eventHandlerShim(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg);

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

int eventHandlerShim(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    void* lr = __builtin_frame_address(0);
    if (event != kEventInit) return 0;
    
    playdate->system->logToConsole(NAME_AND_VERSION "\n");
    playdate->system->logToConsole("LR: %p\nSegment Start: %x\n", lr, SEGMENT_START);
    
    playdate->system->logToConsole("PDBoot entrypoint: %p\n", &_entrypoint_);
    
    playdate->system->setUpdateCallback(update, NULL);
    
    // paranoia; force compiler to include this
    reserved[sizeof(reserved) - 1] = 0;
    
    // wait a bit to flush the console
    wait();
    
    // this HAS to tail-call
    return bootstrap(playdate, event, arg);
}

#endif