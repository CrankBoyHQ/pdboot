#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import sys
import struct
import traceback

MAGIC = b'\xAAPDBoot\x01'
VERSION = 1

R_ARM_ABS32 = 2
R_ARM_TARGET1 = 38

def get_section_addresses(elf):
    print("=== Section Load Addresses ===")
    sections = {
        '.text': None,
        '.rodata': None,
        '.data': None,
        '.bss': None
    }
    
    for section in elf.iter_sections():
        sections[section.name] = section['sh_addr']
        print(f"{section.name:8} -> 0x{section['sh_addr']:08x}")
    
    return sections

def elf2bin(elf_path, bin_path, apply_offset):
    with open(elf_path, 'rb') as elf_file, open(bin_path, 'wb') as bin_file:
        elf = ELFFile(elf_file)
        
        sec_addrs = get_section_addresses(elf)
        
        # Check segments
        load_segments = [seg for seg in elf.iter_segments()  if seg['p_type'] == 'PT_LOAD']
        
        if len(load_segments) != 1:
            print(f"Error: Expected 1 loadable segment, found {len(load_segments)}")
            sys.exit(1)
            
        seg = load_segments[0]
        if seg['p_vaddr'] != 0:
            print(f"Error: Segment starts at 0x{seg['p_vaddr']:x}, expected 0x0")
            sys.exit(1)
                
        data = seg.data()

        print(f"Loadable segment range: 0x0-0x{seg['p_memsz']:x}")

        # Print relocation table
        
        relocations = []
        
        entry = elf.header['e_entry']
        
        print(f"Raw entry: 0x{entry:08x}")
        
        if entry != 1:
            print(f"Entrypoint at {entry:08x}, but should be at address 0 (or 1 with THUMB).")
            print(f"Please ensure your linker script places your entrypoint (e.g. eventHandlerShim) at the very start of the code.")
            sys.exit(4)
        
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                # Skip debug relocations
                if section.name.startswith('.rel.debug'):
                    continue
                
                print(f"--- {section.name} ----");
                    
                symbol_table = elf.get_section(section['sh_link'])
                
                for reloc in section.iter_relocations():
                    sym_idx = reloc['r_info_sym']
                    reloc_type = reloc['r_info_type']
                    offset = reloc['r_offset']
                    
                    # Get addend from relocation target
                    try:
                        addend = int.from_bytes(
                            seg.data()[offset:offset+4],
                            byteorder='little'
                        )
                    except IndexError:
                        print(f"0x{reloc['r_offset']:08x}   {get_reloc_type(reloc_type):<14}   ERROR: Outside loaded segment")
                        sys.exit(1)
                    
                    # Handle different symbol cases
                    if sym_idx == 0:  # STN_UNDEF
                        print(f"0x{reloc['r_offset']:08x}   {get_reloc_type(reloc_type):<14}   ABSOLUTE: 0x{addend:x}")
                        sys.exit(2)
                    elif "UNKNOWN" in get_reloc_type(reloc_type):
                        print(f"Unsupported relocation type {reloc_type}; please implement support for this type.")
                        print("Documentation: https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#relocation-codes-table")
                        sys.exit(5)
                    else:
                        try:
                            sym = symbol_table.get_symbol(sym_idx)
                            name = sym.name if sym.name else "(unnamed)"
                            # For section references
                            sec_idx = sym['st_shndx']
                            sym_value = sym['st_value']
                            if sec_idx == 'SHN_UNDEF':
                                print(f"0x{reloc['r_offset']:08x}   {get_reloc_type(reloc_type):<14}   UNDEFINED_SECTION + 0x{addend:x}")
                                sys.exit(3)
                            else:
                                sec = elf.get_section(sec_idx)
                                print(f"0x{reloc['r_offset']:08x}   {get_reloc_type(reloc_type):<14}   B(S)={sec.name}({sec_addrs[sec.name]:08x}) + S={sym_value:08x} A={addend:08x} {name}")
                                
                                relocations.append((reloc_type, reloc['r_offset'], sym_value, addend))
                        except Exception as e:
                            print(f"0x{reloc['r_offset']:08x}   {get_reloc_type(reloc_type):<14}   UNKNOWN_SYMBOL_{sym_idx} (error: {str(e)})")
                            traceback.print_exc()
                            sys.exit(4)
        
        # bin data
        bin_file.write(data)
        
    print(f"Offset: 0x{apply_offset:08x}")
        
    with open(bin_path, 'r+b') as bin_file:
        # abs32 relocations
        for reloc in relocations:
            reloc_type, r_offset, sym_value, addend = reloc
            if reloc_type in [R_ARM_ABS32, R_ARM_TARGET1]:
                
                # seek to r_offset in binary file, then add `apply_offset` to the 32-bit value there.
                bin_file.seek(r_offset)
                val_bytes = bin_file.read(4)
                val = int.from_bytes(val_bytes, byteorder='little', signed=False)
                newval = (val + apply_offset) & 0xFFFFFFFF
                print(f"Applying offset at 0x{r_offset:08x}: 0x{val:08x} -> 0x{newval:08x}")
                bin_file.seek(r_offset)
                bin_file.write(newval.to_bytes(4, byteorder='little'))
                    
    
    
        # remove any trailing 0s
        print(f"wrote file to {bin_path}")
        bin_file.seek(0, 2)  # Seek to end
        filesize = bin_file.tell()
        bin_file.seek(0)
        data = bytearray(bin_file.read())
    
    # Find last non-zero byte
    last_nonzero = len(data)
    while last_nonzero > 0 and data[last_nonzero-1] == 0:
        last_nonzero -= 1
    
    if last_nonzero < filesize:
        print(f"Truncating from {filesize} to {last_nonzero} bytes")
        with open(bin_path, 'wb') as f:
            f.write(data[:last_nonzero])

used = set()

def get_reloc_type(type_val):
    """Convert relocation type number to human-readable name"""
    arm_relocs = {
        R_ARM_ABS32: "R_ARM_ABS32",
        3: "R_ARM_REL32",
        10: "R_ARM_THM_CALL",
        25: "R_ARM_BASE_PREL",
        30: "R_ARM_THM_JUMP24",
        R_ARM_TARGET1: "R_ARM_TARGET1",
    }
    
    used.add(type_val)
    return arm_relocs.get(type_val, f'UNKNOWN({type_val})')

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} input.elf output.bin offset")
        sys.exit(1)
    
    elf2bin(sys.argv[1], sys.argv[2], int(sys.argv[3], 0))
    
    print("relocation types used: ", [get_reloc_type(e) for e in used])