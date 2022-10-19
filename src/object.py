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
    c_uint,
    c_ubyte,
    c_ushort,
    Structure,
    c_ulonglong
)

from typing import *
from enum import Enum
from dataclasses import dataclass


"""
-   src/parser.py
-   Date: 10/19/22
-   Author: @xmmword
"""


class ElfConstants(Enum):
    ELF_MAGIC: bytes = b"\x7fELF"
    ELF_CLASS64: bytes = bytes(0x02)

    ELF_EV_NONE: bytes = bytes(0x00)
    ELF_EV_CURRENT: bytes = bytes(0x01)

    ELF_ET_DYN: bytes = bytes(0x03)
    ELF_ET_REL: bytes = bytes(0x01)
    ELF_ET_CORE: bytes = bytes(0x04)
    ELF_ET_EXEC: bytes = bytes(0x02)
    ELF_ET_NONE: bytes = bytes(0x00)

    ELF_DATANONE: bytes = bytes(0x00)
    ELF_DATA2LSB: bytes = bytes(0x01)
    ELF_DATA2MSB: bytes = bytes(0x02)

    ELF_EM_X86_64: bytes = bytes(0x3E)

class ElfHeader(Structure):
    """_summary_

    Args:
        Structure (_type_): _description_
    """
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

@dataclass
class ElfObject:
    """Class representation of the ELF file."""
    
    header: ElfHeader = ElfHeader()