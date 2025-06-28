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

UDEFS = -DHEAP_SIZE=$(HEAP_SIZE) -fPIE -pie -fno-plt

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