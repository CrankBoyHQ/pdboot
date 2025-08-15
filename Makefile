HEAP_SIZE      = 12582312
STACK_SIZE     = 61800

PRODUCT = PDBoot.pdx

SDK = ${PLAYDATE_SDK_PATH}
ifeq ($(SDK),)
	SDK = $(shell egrep '^\s*SDKRoot' ~/.Playdate/config | head -n 1 | cut -c9-)
endif

ifeq ($(SDK),)
	$(error SDK path not found; set ENV value PLAYDATE_SDK_PATH)
endif

override SRC = pdboot.c

UDEFS = -DHEAP_SIZE=$(HEAP_SIZE)

# Define ASM defines here
UADEFS =

# List the user directory to look for the libraries here
ULIBDIR =

# List all user libraries here
ULIBS =

override LDSCRIPT = ./link_map.ld

include $(SDK)/C_API/buildsupport/common.mk

# Add --quiet to pdc to suppress informational warnings
PDCFLAGS += --quiet

DYLIB_FLAGS += -DHEAP_SIZE=$(HEAP_SIZE)

# test apps

app.elf: test.o setup.o $(LDSCRIPT)
	$(CC) $^ -nostartfiles -MD -MP -MF  $(MCFLAGS) -T$(LDSCRIPT) -Wl,--cref,--gc-sections,--no-warn-mismatch,--emit-relocs -o $@
	
test.o: test.c
	$(CC) -c $(MCFLAGS) $(DDEFS) $(INCDIR) $< -o $@

setup.o: $(SDK)/C_API/buildsupport/setup.c
	$(CC) -c $(MCFLAGS) $(DDEFS) $(INCDIR) $< -o $@

Source/appB.pdb: appB.elf
	arm-none-eabi-objcopy \
    --image-base=0x90000000 \
    --input-target=elf32-littlearm \
    --output-target=binary \
    $@ \
    $^
	
appB.elf: Source/pdex.elf
	arm-none-eabi-ld \
	-T relocateB.ld -o \
    $@ \
    $^
	
# clean-test, cleans the everything from app.elf to appB.elf
clean-test:
	rm -f app.elf test.o setup.o Source/appB.pdb appB.o appB.elf