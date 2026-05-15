# PDBoot

A boot shim that launches another Playdate C application by loading a stock `pdex.bin` directly.

## Limitations

- Only Pure-C Playdate games. Lua is not yet supported (needs more understanding of `.pdz` format).
- Heap size must be specified on the pdboot build at build time (`HEAP_SIZE` in the pdboot Makefile), which fixes the maximum size of the loaded program.
- Encrypted `pdex.bin` (such as for Catalog builds) are not supported.

## How to use

### Building your payload

For the most part, you can build your playdate application like normal. However, you'll need to add a special routine as an entrypoint, and use a custom `link_map.ld` linker script to ensure that your entrypoint aligns with PDBoot's.

Include this in the same file as your `EventHandler` in C:

```
#include "pd_api.h"

#define PDBOOT_MAIN
#include "pdboot.h"
```

And your `link_map.ld` should have `ENTRY(_entrypoint_)` as the entrypoint, and the very first symbol at offset 0 should be said `_entrypoint_` function. See [testapp](./testapp/link_map.ld) as an example.

### PDBoot

Build PDBoot:

```bash
make -j 4
```

Rename your normal `pdex.bin` to something else, like `app.bin`. Then, drop PDBoot's `pdex.bin` into your target pdx, and place your payload(s) at the matching locations.

Add a plain-text `pdboot` file alongside the binaries that lists candidate payload paths, one per line. PDBoot tries each in order and launches the first one that opens. If no `pdboot` file is present, PDBoot defaults to just checking for a file called "`app.bin`" (in pdx or data dir).

`pdboot` example:

```
# blank lines and lines starting with '#' are ignored.
pdx:./app.bin
data:./app.bin
/Shared/.pdboot/app.bin
```

Path prefixes select which filesystem `playdate->file->open` searches:

- `pdx:PATH`: `kFileRead` (pdx bundle only)
- `data:PATH`: `kFileReadData` (per-game data dir only)
- anything else: `kFileRead | kFileReadData` (search both)

Launching PDboot's `pdex.bin` should then print some diagnostic information out to the console and then launch your `app.bin`.

## Detecting PDBoot from the loaded app

Include `pdboot.h` to read the boot metadata stashed at `playdate->graphics->getFrame()`:

```c
#include "pdboot.h"

const pdboot_data_t* d = (const pdboot_data_t*)(void*)playdate->graphics->getFrame();
if (memcmp(d->magic, PDBOOT_MAGIC, 8) == 0) {
    // launched by pdboot. Read d->name_and_version, d->version_major/minor, etc.
}
```

## Test app

In this repo, `testapp/` is a minimal C payload that logs `hello from payload` in `kEventInit`, detects PDBoot via the framebuffer magic, and renders some text because why not.

```bash
# build PDBoot
make -j 4

# build test payload
(cd testapp && make -j 4)

# add test payload to PDBoot.pdx
cp testapp/TestPayload.pdx/pdex.bin PDBoot.pdx/app.bin

# (then sideload PDBoot.pdx onto a device and launch it)
```

If you look at the console, you should see messages from `PDBoot` ending with `[PDBoot] handing off...` and then the test app's output should follow.

## Dependencies

- `uzlib/` ([source](https://github.com/pfalcon/uzlib)) (ZLib license)