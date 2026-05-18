# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

"""Minimal big-endian 32-bit ELF object file builder."""
import struct

# ELF identity
ELFMAG       = b'\x7fELF'
ELFCLASS32   = 1
ELFDATA2MSB  = 2
EV_CURRENT   = 1

# e_type
ET_REL = 1

# e_machine
EM_SH   = 0x0002
EM_M32R = 0x0058

# sh_type
SHT_NULL     = 0
SHT_PROGBITS = 1
SHT_SYMTAB   = 2
SHT_STRTAB   = 3

# sh_flags
SHF_ALLOC = 0x2

# st_info binding / type
STB_LOCAL  = 0
STB_GLOBAL = 1
STT_OBJECT = 1

# st_shndx special values
SHN_UNDEF = 0
SHN_ABS   = 0xfff1

EHDR_SIZE = 52   # ELF32 header
SHDR_SIZE = 40   # ELF32 section header
SYM_SIZE  = 16   # ELF32 symbol table entry


def _pack_ehdr(machine, shoff, shnum, shstrndx):
    e_ident = (ELFMAG +
               bytes([ELFCLASS32, ELFDATA2MSB, EV_CURRENT]) +
               b'\x00' * 9)
    return struct.pack('>16sHHIIIIIHHHHHH',
        e_ident,
        ET_REL, machine,
        EV_CURRENT,
        0,          # e_entry
        0,          # e_phoff
        shoff,
        0,          # e_flags
        EHDR_SIZE,
        0, 0,       # e_phentsize, e_phnum
        SHDR_SIZE,
        shnum,
        shstrndx,
    )


def _pack_shdr(sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
               sh_link=0, sh_info=0, sh_addralign=4, sh_entsize=0):
    return struct.pack('>IIIIIIIIII',
        sh_name, sh_type, sh_flags, sh_addr,
        sh_offset, sh_size, sh_link, sh_info,
        sh_addralign, sh_entsize,
    )


def pack_sym(st_name, st_value, st_size, st_info, st_other, st_shndx):
    return struct.pack('>IIIBBH',
        st_name, st_value, st_size, st_info, st_other, st_shndx,
    )


class ELFBuilder:
    """Builds a minimal big-endian 32-bit ET_REL ELF."""

    def __init__(self, machine):
        self.machine = machine
        self._sections = []

    def add_section(self, name, data, sh_type=SHT_PROGBITS, sh_flags=SHF_ALLOC,
                    sh_addr=0, sh_link=0, sh_info=0, sh_entsize=0, sh_addralign=4):
        """Add a section and return its 1-based section index."""
        idx = 1 + len(self._sections)
        self._sections.append(dict(
            name=name, data=data, sh_type=sh_type, sh_flags=sh_flags,
            sh_addr=sh_addr, sh_link=sh_link, sh_info=sh_info,
            sh_entsize=sh_entsize, sh_addralign=sh_addralign,
        ))
        return idx

    def build(self):
        # Build .shstrtab — contains names of all sections + itself
        shstrtab = b'\x00'
        name_offsets = {}

        def _strtab_add(name):
            nonlocal shstrtab
            if name not in name_offsets:
                name_offsets[name] = len(shstrtab)
                shstrtab += name.encode() + b'\x00'

        for s in self._sections:
            _strtab_add(s['name'])
        _strtab_add('.shstrtab')

        shstrndx = 1 + len(self._sections)   # null + user sections + shstrtab
        total_shnum = shstrndx + 1

        # Lay out: ELF header | section data... | shstrtab | section headers
        buf = bytearray(EHDR_SIZE)
        section_offsets = []

        for s in self._sections:
            align = s['sh_addralign']
            if align > 1 and len(buf) % align:
                buf += b'\x00' * (align - len(buf) % align)
            section_offsets.append(len(buf))
            buf += s['data']

        # shstrtab
        if len(buf) % 4:
            buf += b'\x00' * (4 - len(buf) % 4)
        shstrtab_offset = len(buf)
        buf += shstrtab

        # section headers
        if len(buf) % 4:
            buf += b'\x00' * (4 - len(buf) % 4)
        shoff = len(buf)

        # null section header
        buf += _pack_shdr(0, SHT_NULL, 0, 0, 0, 0)

        for i, s in enumerate(self._sections):
            buf += _pack_shdr(
                name_offsets[s['name']], s['sh_type'], s['sh_flags'], s['sh_addr'],
                section_offsets[i], len(s['data']),
                s['sh_link'], s['sh_info'], s['sh_addralign'], s['sh_entsize'],
            )

        # .shstrtab header
        buf += _pack_shdr(
            name_offsets['.shstrtab'], SHT_STRTAB, 0, 0,
            shstrtab_offset, len(shstrtab),
            0, 0, 1, 0,
        )

        # Patch ELF header at offset 0
        buf[:EHDR_SIZE] = _pack_ehdr(self.machine, shoff, total_shnum, shstrndx)
        return bytes(buf)
