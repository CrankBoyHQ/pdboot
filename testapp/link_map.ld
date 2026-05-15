/*
	PDBoot-compatible linker script.
	
	Entrypoint must be specified as _entrypoint_ 
	
	(_entrypoint_ is a short trampoline in c to eventHandlerShim)
*/
ENTRY(_entrypoint_)

SECTIONS
{
	.text :
	{
		/* ... and the _entrypoint_ function must be placed at the very start */
		*(.entry)

		*(.text)
		*(.text.*)
		
		*(.rodata*)
	}

	.data :
	{
		__etext = .;

		__data_start__ = .;
		*(.data*)

		. = ALIGN(4);
		__data_end__ = .;
	}

	.bss :
	{
		. = ALIGN(4);
		__bss_start__ = .;
		*(.bss*)
		. = ALIGN(4);
		__bss_end__ = .;
	}

	/DISCARD/ :
	{
		*(.ARM.exidx)
	}
}
