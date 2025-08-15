ENTRY(_entrypoint_)
GROUP(libgcc.a libc.a libm.a)

SECTIONS
{
	.text :
	{        	
		__text_start__ = .;
		
		*(.entry)
		
		__boot_start__ = .;
		
		*(.boot)
		
		*(.text)
		*(.text.*)
        
		KEEP(*(.init))
		KEEP(*(.fini))
		
		. = ALIGN(32);
	}

	.data :
	{
		__etext = .;
		
		. = ALIGN(32);

		__data_start__ = .;
		*(vtable)
		*(.data*)

		. = ALIGN(4);
		/* preinit data */
		PROVIDE_HIDDEN (__preinit_array_start = .);
		KEEP(*(.preinit_array))
		PROVIDE_HIDDEN (__preinit_array_end = .);

		. = ALIGN(4);
		/* init data */
		PROVIDE_HIDDEN (__init_array_start = .);
		KEEP(*(SORT(.init_array.*)))
		KEEP(*(.init_array))
		PROVIDE_HIDDEN (__init_array_end = .);

		. = ALIGN(4);
		/* finit data */
		PROVIDE_HIDDEN (__fini_array_start = .);
		KEEP(*(SORT(.fini_array.*)))
		KEEP(*(.fini_array))
		PROVIDE_HIDDEN (__fini_array_end = .);

		. = ALIGN(4);
		/* All data end */
		__data_end__ = .;

	}

	.bss :
	{
		. = ALIGN(32);
		__bss_start__ = .;
		*(.bss*)
		*(.reserved)
		*(COMMON)
		*(COM)
		. = ALIGN(4);
		__bss_end__ = .;
	}

  /DISCARD/ :
  {
		*(.ARM.exidx)
  }

}
