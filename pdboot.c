#include <string.h>

#define PDBOOT_CONFIG_FILE "pdboot"

#define NAME_AND_VERSION "PDBoot v2.0"
#define PDB_VERSION_MAJOR 2
#define PDB_VERSION_MINOR 0

#include "pd_api.h"
#include "pdboot.h"
#include "uzlib/uzlib.h"

#define MEM_SIZE 16000000

#ifndef TARGET_SIMULATOR
__attribute__((
    section(".reserved"))) volatile char reserved[MEM_SIZE - HEAP_SIZE];
#endif

int update(void *ud) { return 0; }

int eventHandler(PlaydateAPI *playdate, PDSystemEvent event, uint32_t arg) {
  playdate->system->setUpdateCallback(update, NULL);
  playdate->system->logToConsole("\n[ERROR] PDBoot only works on actual hardware.\n");
  return 0;
}

#ifndef TARGET_SIMULATOR

#define $ "\n\t"

#define __boot __attribute__((short_call)) __attribute__((section(".boot")))

extern char __text_start__, __boot_start__, __boot_end__, __data_end__;

#define BOOT_SIZE ((uintptr_t)(&__boot_end__ - &__boot_start__))

__attribute__((noinline)) static uintptr_t get_base_addr(void) {
  return ((uintptr_t)(void *)&get_base_addr) & 0xFF000000;
}

#define REV_A 0
#define REV_B 1
#define REV_UNKNOWN 2

const char *REV_CHAR = "ABCDEF";

static int get_rev(uintptr_t base_addr) {
  if (base_addr == 0x60000000)
    return REV_A;
  if (base_addr == 0x90000000)
    return REV_B;
  return REV_UNKNOWN;
}

__boot static void wait(void) {
  for (int i = 0; i < 1600000; ++i) {
    asm("nop");
  }
}

typedef int (*entrypoint_t)(PlaydateAPI *playdate, PDSystemEvent event,
                            uint32_t arg);
typedef void (*wait_t)(void);

__boot __attribute__((naked)) void hard_jump_to_entrypoint(
    // r0-r3
    PlaydateAPI *playdate, PDSystemEvent event, uint32_t arg, void *regs) {
  // clang-format off
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
        "dsb"$
        "isb"$
        "bx     r3"$
    );
    // bclang-format on
}

__boot static
void hexbyte(char* out, uint8_t v)
{
    uint8_t hi = v >> 4;
    uint8_t lo = v & 0xf;
    out[0] = (hi < 10) ? ('0' + hi) : ('A' + hi - 10);
    out[1] = (lo < 10) ? ('0' + lo) : ('A' + lo - 10);
}

// -fno-tree-loop-distribute-patterns: keep the byte-by-byte loops inline
// instead of replacing them with `bl memset` / `bl memcpy`
__boot
__attribute__((optimize("-fno-tree-loop-distribute-patterns")))
static void bootstrap(
    // r0-r3
    PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,

    // stack-allocated args
    char* buff, size_t size, wait_t wait,
    pdboot_data_t* data
)
{
    wait();

    // copy loaded image into the reserved region at base_addr
    for (size_t i = 0; i < size; ++i)
    {
        ((char*)base_addr)[i] = buff[i];
    }

    wait();

    // zero the rest of the reserved region (covers BSS up to MEM_SIZE-HEAP_SIZE)
    for (size_t i = size; i < MEM_SIZE - HEAP_SIZE; ++i)
    {
        ((char*)base_addr)[i] = 0;
    }
    wait();

    playdate->system->realloc(buff, 0);

    wait();

    playdate->system->clearICache();
    
    char msg[40];
    int i = 0;
    
    // (can't use regular strings at this point anymore, since the 
    // text region is now invalid)
    
    // clang-format off
    msg[i++] = '['; msg[i++] = 'P'; msg[i++] = 'D';
    msg[i++] = 'B'; msg[i++] = 'o'; msg[i++] = 'o';
    msg[i++] = 't'; msg[i++] = ']'; msg[i++] = ' ';
    msg[i++] = 'h'; msg[i++] = 'a'; msg[i++] = 'n';
    msg[i++] = 'd'; msg[i++] = 'i'; msg[i++] = 'n';
    msg[i++] = 'g'; msg[i++] = ' '; msg[i++] = 'o';
    msg[i++] = 'f'; msg[i++] = 'f'; msg[i++] = '.';
    msg[i++] = '.'; msg[i++] = '.'; msg[i++] = 0;
    // clang-format on
    
    playdate->system->logToConsole(msg);
    wait();

    hard_jump_to_entrypoint(playdate, event, arg, data->regs);
}

// ============================================================
// pdex.bin header
// ============================================================

typedef struct {
    char     sig[12];     // "Playdate PDX" or "Playdate BIN"
    uint32_t flags;
    uint8_t  md5[16];
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t e_entry;
    uint32_t nreloc;
} pdex_hdr_t;

#define PDEX_FLAG_ENCRYPTED 0x40000000u

#define UZLIB_INBUF_SIZE 1024
static SDFile* g_uzlib_file;
static PlaydateAPI* g_uzlib_pd;
static unsigned char g_uzlib_inbuf[UZLIB_INBUF_SIZE];

static int uzlib_source_read(struct uzlib_uncomp *d)
{
    int n = g_uzlib_pd->file->read(g_uzlib_file, g_uzlib_inbuf, UZLIB_INBUF_SIZE);
    if (n <= 0) return -1;
    d->source = g_uzlib_inbuf + 1;
    d->source_limit = g_uzlib_inbuf + n;
    return g_uzlib_inbuf[0];
}

static void* regs[11];

int _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg);

#define FB_SIZE 12000

static uint8_t* fb_alloc_cursor;
static uint8_t* fb_alloc_end;

static void fb_alloc_init(PlaydateAPI* pd)
{
    uint8_t* fb = (uint8_t*)pd->graphics->getFrame();
    fb_alloc_cursor = fb + sizeof(pdboot_data_t);
    fb_alloc_end    = fb + FB_SIZE;
}

static void* fb_alloc(size_t size, size_t align)
{
    uintptr_t p = (uintptr_t)fb_alloc_cursor;
    p = (p + align - 1) & ~(uintptr_t)(align - 1);
    if (p + size > (uintptr_t)fb_alloc_end) return NULL;
    fb_alloc_cursor = (uint8_t*)(p + size);
    return (void*)p;
}

static void hexdump(PlaydateAPI* pd, const char* label, const void* p, size_t n)
{
    if (n > 32) n = 32;
    const uint8_t* b = (const uint8_t*)p;
    char line[16 + 32*3 + 4 + 32 + 1];
    char* w = line;
    for (size_t i = 0; i < n; ++i)
    {
        static const char hex[] = "0123456789abcdef";
        *w++ = hex[b[i] >> 4];
        *w++ = hex[b[i] & 0xf];
        *w++ = ' ';
    }
    *w++ = ' ';
    *w++ = '|';
    for (size_t i = 0; i < n; ++i)
    {
        char c = (char)b[i];
        *w++ = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    *w++ = '|';
    *w = 0;
    pd->system->logToConsole("[PDBoot] %s @%p: %s", label, p, line);
}

#define BAIL(...) do { \
    playdate->system->logToConsole("[PDBoot FAIL] " __VA_ARGS__); \
    playdate->system->error(__VA_ARGS__); \
} while (0)

int pdboot_main(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    void* fp = regs[8];
    void* lr = regs[9];
    void* sp = regs[10];

    if (event != kEventInit) return 0;

    playdate->system->logToConsole("[PDBoot] %s (%d/%x)", NAME_AND_VERSION, (int)event, (unsigned)arg);
    playdate->system->logToConsole("[PDBoot] entrypoint=%p &pdboot_main=%p",
        &_entrypoint_, &pdboot_main);
    playdate->system->logToConsole("[PDBoot] &__boot_start__=%p &__boot_end__=%p &__data_end__=%p BOOT_SIZE=0x%x",
        &__boot_start__, &__boot_end__, &__data_end__, (unsigned)BOOT_SIZE);
    playdate->system->logToConsole("[PDBoot] &reserved=%p sizeof(reserved)=0x%x sizeof(pdboot_data_t)=%u",
        (void*)reserved, (unsigned)sizeof(reserved), (unsigned)sizeof(pdboot_data_t));

    if (arg >= 2)
    {
        playdate->system->logToConsole("[PDBoot] depth limit exceeded (arg=%u), stopping here.", (unsigned)arg);
        return 0;
    }
    arg++;

    uintptr_t base_addr = get_base_addr();
    int rev = get_rev(base_addr);
    char rev_char = (rev == REV_UNKNOWN) ? '?' : REV_CHAR[rev];

    playdate->system->logToConsole("[PDBoot] LR=%p SP=%p FP=%p base=0x%08x rev=%c",
        lr, sp, fp, (unsigned)base_addr, rev_char);
    wait();

    if (rev == REV_UNKNOWN)
    {
        BAIL("Unrecognized hardware base 0x%08x. PDBoot supports Rev A (0x60000000) and Rev B (0x90000000) only.",
             (unsigned)base_addr);
        return 0;
    }

    // -- read 'pdboot' config file (line-based; optional) --
    //
    // Format:
    //   - one path per line
    //   - blank lines and '#'-prefixed comment lines are skipped
    //   - optional 'pdx:' or 'data:' prefix selects the filesystem
    //     (no prefix -> search both, same as kFileRead|kFileReadData)
    //
    // If 'pdboot' is not present, default to a single entry "app.bin".
    SDFile* file = NULL;
    const char* opened_path = NULL;
    SDFile* cfg_file = playdate->file->open(PDBOOT_CONFIG_FILE,
                                            kFileRead | kFileReadData);
    if (!cfg_file)
    {
        playdate->system->logToConsole(
            "[PDBoot] no '%s' present, defaulting to 'app.bin'", PDBOOT_CONFIG_FILE);
        file = playdate->file->open("app.bin", kFileRead | kFileReadData);
        if (file) opened_path = "app.bin";
    }
    else
    {
        char cfg_buf[4096];
        int cfg_n = playdate->file->read(cfg_file, cfg_buf, sizeof(cfg_buf) - 1);
        playdate->file->close(cfg_file);
        if (cfg_n < 0)
        {
            BAIL("failed to read '%s': %d", PDBOOT_CONFIG_FILE, cfg_n);
            return 0;
        }
        cfg_buf[cfg_n] = 0;
        playdate->system->logToConsole("[PDBoot] '%s': %d bytes read",
            PDBOOT_CONFIG_FILE, cfg_n);

        int line_idx = 0;
        char* p = cfg_buf;
        char* end = cfg_buf + cfg_n;
        while (p < end && !file)
        {
            char* line = p;
            while (p < end && *p != '\n' && *p != '\r') p++;
            char* line_end = p;
            while (p < end && (*p == '\n' || *p == '\r')) p++;

            while (line < line_end && (*line == ' ' || *line == '\t')) line++;
            while (line_end > line && (line_end[-1] == ' ' || line_end[-1] == '\t')) line_end--;

            if (line == line_end) continue;   // empty
            if (*line == '#')      continue;  // comment
            *line_end = 0;

            const char* path = line;
            int flags = kFileRead | kFileReadData;
            if (line_end - line >= 4 && memcmp(line, "pdx:", 4) == 0)
            {
                path = line + 4;
                flags = kFileRead;
            }
            else if (line_end - line >= 5 && memcmp(line, "data:", 5) == 0)
            {
                path = line + 5;
                flags = kFileReadData;
            }
            playdate->system->logToConsole(
                "[PDBoot] trying app[%d] '%s' (orig='%s' flags=0x%x)",
                line_idx, path, line, flags);
            file = playdate->file->open(path, flags);
            if (file)
            {
                opened_path = path;
                playdate->system->logToConsole(
                    "[PDBoot] opened app[%d] '%s'", line_idx, path);
            }
            line_idx++;
        }
    }

    if (!file)
    {
        BAIL("no bootable app found");
        return 0;
    }
    (void)opened_path;

    fb_alloc_init(playdate);
    uint8_t* bs_region = (uint8_t*)fb_alloc(BOOT_SIZE, 4);
    if (!bs_region)
    {
        BAIL("framebuffer alloc for boot stub (%u bytes) failed", (unsigned)BOOT_SIZE);
        return 0;
    }
    playdate->system->logToConsole("[PDBoot] fb_alloc: bs_region=%p (%u bytes)",
        bs_region, (unsigned)BOOT_SIZE);

    // read 0x30-byte pdex header
    pdex_hdr_t hdr;
    int nread = playdate->file->read(file, &hdr, sizeof(hdr));
    if (nread != (int)sizeof(hdr))
    {
        BAIL("pdex header short read: %d/%d", nread, (int)sizeof(hdr));
        playdate->file->close(file);
        return 0;
    }

    playdate->system->logToConsole("[PDBoot] header read: %d bytes", nread);

    // confirm magic ("Playdate"), case-insensitive
    {
        static const char kMagic[8] = { 'P','L','A','Y','D','A','T','E' };
        int ok = 1;
        for (int i = 0; i < 8; ++i)
        {
            char c = hdr.sig[i];
            if (c >= 'a' && c <= 'z') c -= ('a' - 'A');
            if (c != kMagic[i]) { ok = 0; break; }
        }
        if (!ok)
        {
            BAIL("Not a recognized pdex.bin: magic \"Playdate\" missing (got \"%c%c%c%c%c%c%c%c\")",
                hdr.sig[0],hdr.sig[1],hdr.sig[2],hdr.sig[3],
                hdr.sig[4],hdr.sig[5],hdr.sig[6],hdr.sig[7]);
            playdate->file->close(file);
            return 0;
        }
    }

    if (hdr.flags & PDEX_FLAG_ENCRYPTED)
    {
        BAIL("Encrypted pdex.bin not supported (flags=0x%08x)", hdr.flags);
        playdate->file->close(file);
        return 0;
    }

    uint32_t expected_entry = (uint32_t)((uintptr_t)(void*)&_entrypoint_ - base_addr);
    if (hdr.e_entry != expected_entry)
    {
        BAIL("payload e_entry=0x%x but PDBoot expects 0x%x (offset of own _entrypoint_); was this bin not compiled with a correct link_map.ld?",
            hdr.e_entry, expected_entry);
        playdate->file->close(file);
        return 0;
    }

    playdate->system->logToConsole("[PDBoot] p_filesz=0x%x (%u) p_memsz=0x%x (%u)",
        hdr.p_filesz, hdr.p_filesz, hdr.p_memsz, hdr.p_memsz);
    playdate->system->logToConsole("[PDBoot] e_entry=0x%x nreloc=%u reserved_region=0x%x (%u)",
        hdr.e_entry, hdr.nreloc,
        (unsigned)(MEM_SIZE - HEAP_SIZE), (unsigned)(MEM_SIZE - HEAP_SIZE));

    size_t total = (size_t)hdr.p_filesz + (size_t)hdr.nreloc * 4u;

    playdate->system->logToConsole("[PDBoot] allocating 0x%X bytes for decompression buffer",
        (unsigned)total);
    char* dec = playdate->system->realloc(NULL, total);
    if (!dec)
    {
        playdate->file->close(file);
        BAIL("Failed to allocate %u bytes for decompression buffer", (unsigned)total);
        return 0;
    }

    // streaming zlib inflate from SDFile
    playdate->system->logToConsole("[PDBoot] streaming inflate from disk...");
    uzlib_init();

    struct uzlib_uncomp d;
    memset(&d, 0, sizeof(d));
    g_uzlib_file = file;
    g_uzlib_pd = playdate;
    d.source = NULL;
    d.source_limit = NULL;
    d.source_read_cb = uzlib_source_read;
    d.dest = (unsigned char*)dec;
    d.dest_start = (unsigned char*)dec;
    d.dest_limit = (unsigned char*)dec + total;

    uzlib_uncompress_init(&d, NULL, 0);

    int hres = uzlib_zlib_parse_header(&d);
    if (hres < 0)
    {
        playdate->system->realloc(dec, 0);
        playdate->file->close(file);
        BAIL("zlib header parse failed: %d", hres);
        return 0;
    }
    playdate->system->logToConsole("[PDBoot] zlib header OK (%d)", hres);

    int ires = uzlib_uncompress(&d);
    if (ires < 0)
    {
        playdate->system->realloc(dec, 0);
        playdate->file->close(file);
        BAIL("inflate failed (%d)", ires);
        return 0;
    }

    size_t produced = (size_t)(d.dest - d.dest_start);
    playdate->system->logToConsole("[PDBoot] inflate result=%d; %u bytes decompressed (%u expected)",
        ires, (unsigned)produced, (unsigned)total);

    if (produced != total)
    {
        playdate->system->realloc(dec, 0);
        playdate->file->close(file);
        BAIL("inflate size mismatch: is %u, expected %u",
            (unsigned)produced, (unsigned)total);
        return 0;
    }

    playdate->file->close(file);

    // apply relocations: each entry is an offset within the segment;
    // add base_addr to the u32 stored at that offset.
    uint32_t* relocs = (uint32_t*)(dec + hdr.p_filesz);
    uint32_t logged = 0;
    playdate->system->logToConsole("[PDBoot] applying %u relocations against base 0x%08x", hdr.nreloc, (unsigned)base_addr);
    for (uint32_t i = 0; i < hdr.nreloc; ++i)
    {
        uint32_t off = relocs[i];
        uint32_t before = *(uint32_t*)(dec + off);
        uint32_t after  = before + base_addr;
        *(uint32_t*)(dec + off) = after;
    }
    wait();
    playdate->system->logToConsole("[PDBoot] relocations applied.");

    // Trim trailing zeros -- the bootstrap zero-fills past the copy anyway.
    size_t copy_size = hdr.p_filesz;
    while (copy_size > 0 && ((unsigned char*)dec)[copy_size - 1] == 0) copy_size--;
    copy_size = (copy_size + 3u) & ~(size_t)3u;
    if (copy_size > MEM_SIZE - HEAP_SIZE)
    {
        BAIL("loaded image (%u after trim) exceeds reserved region (%u)",
            (unsigned)copy_size, (unsigned)(MEM_SIZE - HEAP_SIZE));
        playdate->system->realloc(dec, 0);
        return 0;
    }
    playdate->system->logToConsole("[PDBoot] trimmed copy_size=%u (from p_filesz=%u; %u trailing zeros stripped)",
        (unsigned)copy_size, (unsigned)hdr.p_filesz,
        (unsigned)(hdr.p_filesz - copy_size));

    // hexdump near the entrypoint we'll jump to (must be valid Thumb code)
    if (hdr.e_entry < hdr.p_filesz)
    {
        uintptr_t ent_off = hdr.e_entry & ~1u;
        hexdump(playdate, "entry routine", dec + ent_off, 32);
    }

    pdboot_data_t* data = (pdboot_data_t*)playdate->graphics->getFrame();

    memset(data, 0, sizeof(*data));
    strcpy(data->magic, PDBOOT_MAGIC);
    strcpy(data->name_and_version, NAME_AND_VERSION);
    data->version_major = PDB_VERSION_MAJOR;
    data->version_minor = PDB_VERSION_MINOR;

    memcpy(data->regs, regs, sizeof(data->regs));
    data->entrypoint = (void*)((uintptr_t)base_addr + (uintptr_t)hdr.e_entry);

    playdate->system->logToConsole("[PDBoot] copying boot stub from %p to %p (size 0x%x bytes)",
        &__boot_start__, bs_region, (unsigned)BOOT_SIZE);

    memcpy(bs_region, &__boot_start__, BOOT_SIZE);

    // paranoia: force the linker to keep the reserved region
    reserved[sizeof(reserved) - 1] = 1;

    // compute shim function pointers (relocated copies of bootstrap & wait)
    uintptr_t boot_orig = (uintptr_t)(void*)&__boot_start__;
    uintptr_t boot_new  = (uintptr_t)(void*)bs_region;

    void (*bootstrap_shim)(
        PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg, void* base_addr,
        char* buff, size_t size, wait_t wait,
        void* data
    ) = (void*)((uintptr_t)(void*)&bootstrap - boot_orig + boot_new);

    wait_t wait_shim = (void*)((uintptr_t)(void*)&wait - boot_orig + boot_new);

    playdate->system->logToConsole("[PDBoot] shim ptrs: bootstrap orig=%p shim=%p   wait orig=%p shim=%p",
        &bootstrap, bootstrap_shim, &wait, wait_shim);
    playdate->system->logToConsole("[PDBoot] final entry: base+e_entry = 0x%08x + 0x%x = %p (Thumb LSB=%d)",
        (unsigned)base_addr, hdr.e_entry, data->entrypoint, hdr.e_entry & 1);
    playdate->system->logToConsole("[PDBoot] entering boot shim...");
    wait();
    wait();

    // (does not return)
    bootstrap_shim(
        playdate, event, arg, (void*)base_addr,
        dec, copy_size, wait_shim,
        data
    );

    // unreachable
    BAIL("bootstrap_shim should not return, but it did");
    return 0;
}

// must align with pdex's entrypoint
__attribute__((section(".entry")))
__attribute__((naked))
int _entrypoint_(PlaydateAPI* playdate, PDSystemEvent event, uint32_t arg)
{
    // clang-format off
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
  // clang-format on
}

#endif
