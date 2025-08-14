#include "pd_api.h"

int update(void* ud)
{
    return 0;
}

int eventHandler(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    playdate->system->setUpdateCallback(update, NULL);
    playdate->system->logToConsole("Hello from test app!.\n");
    return 0;
}

#ifndef TARGET_SIMULATOR

int eventHandlerShim(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg);

// very short entrypoint function that pre-empts the eventHandlerShim.
// This must be located at exactly the segment start, so that it aligns with the
// entrypoint in pdboot
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