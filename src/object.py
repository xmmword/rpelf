"""
   Copyright (C) 2022 xmmword

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

from ctypes import (
    Array,
    c_uint,
    c_char,
    c_ubyte,
    c_ushort,
    Structure,
    c_ulonglong,
    create_string_buffer
)

from dataclasses import (
    field,
    dataclass
)

from typing import (
    Any,
    final,
    Final,
    Sequence
)

from enum import Enum


"""
-   src/object.py
-   Date: 10/22/22
-   Author: @xmmword
"""


@final
class ElfConstants(Enum):
    """Class-Enumeration holding important ELF constants."""

    ELF_PT_LOAD:   Final[bytes] = bytes(0x1)
    ELF_EM_X86_64: Final[bytes] = bytes(0x3E)

    ELF_EV_NONE:    Final[bytes] = bytes(0x00)
    ELF_EV_CURRENT: Final[bytes] = bytes(0x01)

    ELF_MAGIC:   Final[bytes] = b"\x7fELF"
    ELF_CLASS64: Final[bytes] = bytes(0x02)

    ELF_ET_DYN:  Final[bytes] = bytes(0x03)
    ELF_ET_REL:  Final[bytes] = bytes(0x01)
    ELF_ET_CORE: Final[bytes] = bytes(0x04)
    ELF_ET_EXEC: Final[bytes] = bytes(0x02)
    ELF_ET_NONE: Final[bytes] = bytes(0x00)

    ELF_DATANONE: Final[bytes] = bytes(0x00)
    ELF_DATA2LSB: Final[bytes] = bytes(0x01)
    ELF_DATA2MSB: Final[bytes] = bytes(0x02)

class ElfHeader(Structure):
    """Class-Structure containing the ELF header."""

    _fields_: Sequence[tuple[str, type[Any]] | tuple[str, type[Any], int]] = [
        ("e_ident", (c_ubyte * 16)),
        ("e_type", c_ushort),
        ("e_machine", c_ushort),
        ("e_version", c_uint),
        ("e_entry", c_ulonglong),
        ("e_phoff", c_ulonglong),
        ("e_shoff", c_ulonglong),
        ("e_flags", c_uint),
        ("e_ehsize", c_ushort),
        ("e_phentsize", c_ushort),
        ("e_phnum", c_ushort),
        ("e_shentsize", c_ushort),
        ("e_shnum", c_ushort),
        ("e_shstrndx", c_ushort)
    ]

class ElfShdr(Structure):
    """Class-Structure containing the ELF Section Header Table."""

    _fields_: Sequence[tuple[str, type[Any]] | tuple[str, type[Any], int]] = [
        ("sh_name", c_uint),
        ("sh_type", c_uint),
        ("sh_flags", c_ulonglong),
        ("sh_addr", c_ulonglong),
        ("sh_offset", c_ulonglong),
        ("sh_size", c_ulonglong),
        ("sh_link", c_uint),
        ("sh_info", c_uint),
        ("sh_addralign", c_ulonglong),
        ("sh_entsize", c_ulonglong)
    ]

@dataclass
class ElfObject:
    """Class representation of the ELF file."""

    header: ElfHeader = ElfHeader()
    section_header: ElfShdr = ElfShdr()

    string_table: Array[c_char] = create_string_buffer(0)
    section_header_table: tuple[tuple[int, ElfShdr]] = field(default_factory=tuple)