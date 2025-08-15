#pragma once

#define PDBOOT_MAGIC "\xAAPDBoot\x01"

// stored at playdate->system->getFrame().
typedef struct pdboot_data
{
    char magic[8];
    
    char name_and_version[32];
    
    int version_major;
    int version_minor;
    
    char reserved[32];
    
    // for internal pdboot use
    void* regs[11];
    
    // for internal pdboot use
    void* entrypoint;
} pdboot_data_t;