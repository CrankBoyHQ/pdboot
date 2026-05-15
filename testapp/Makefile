HEAP_SIZE      = 8388208
STACK_SIZE     = 61800

PRODUCT = TestPayload.pdx

SDK = ${PLAYDATE_SDK_PATH}
ifeq ($(SDK),)
	SDK = $(shell egrep '^\s*SDKRoot' ~/.Playdate/config | head -n 1 | cut -c9-)
endif

ifeq ($(SDK),)
	$(error SDK path not found; set ENV value PLAYDATE_SDK_PATH)
endif

SRC = main.c

UDEFS =
UADEFS =
ULIBDIR =
ULIBS =

# PDBoot requires the payload's _entrypoint_ at offset 0
override LDSCRIPT = ./link_map.ld

include $(SDK)/C_API/buildsupport/common.mk
