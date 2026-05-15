#include <string.h>

#define PDBOOT_MAIN
#include "pd_api.h"
#include "../pdboot.h"

///// -- Everything that follows is not required for PDBoot, just a simple test app -- /////

// (An example of how to read the provided pdboot data struct is included, though.)

static PlaydateAPI* pd;
static int frames = 0;
static LCDFont* font = NULL;

static int update(void* ud)
{
    pd->graphics->clear(kColorWhite);

    char* buf = NULL;
    int n = pd->system->formatString(&buf, "frame %d", frames++);

    if (font && buf)
    {
        pd->graphics->setFont(font);
        pd->graphics->drawText(buf, n, kASCIIEncoding, 20, 20);
    }
    if (buf) pd->system->realloc(buf, 0);

    pd->system->drawFPS(0, 0);
    return 1;
}

int eventHandler(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    if (event == kEventInit)
    {
        pd = playdate;
        pd->system->logToConsole("hello from payload");

        // check for a pdboot data struct
        const pdboot_data_t* d = (const pdboot_data_t*)pd->graphics->getFrame();
        
        // verify it has a valid pdboot magic header
        if (memcmp(d->magic, PDBOOT_MAGIC, 8) == 0)
        {
            // get info about the pdboot version that launched this payload
            pd->system->logToConsole(
                "launched by %s (v%d.%d)",
                d->name_and_version, d->version_major, d->version_minor);
        }
        else
        {
            pd->system->logToConsole("not launched by pdboot (!)");
        }

        const char* err;
        font = pd->graphics->loadFont("/System/Fonts/Asheville-Sans-14-Bold.pft", &err);
        if (!font) pd->system->logToConsole("font load failed: %s", err ? err : "(null)");

        pd->display->setRefreshRate(60.0f);
        pd->system->setUpdateCallback(update, NULL);
    }
    return 0;
}
