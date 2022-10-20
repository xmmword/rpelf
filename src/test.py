import struct

from typing import (
    Any,
    Sequence
)

from ctypes import (
    c_uint,
    c_ubyte,
    c_ushort,
    Structure,
    c_ulonglong,
    memmove,
    sizeof,
    addressof
)

from enum import Enum
from dataclasses import dataclass

from typing import *

class ElfPhdr(Structure):
    """Class-Structure containing the ELF Program Header Table."""

    _fields_: Sequence[tuple[str, type[Any]] | tuple[str, type[Any], int]] = [
        ("p_type", c_uint),
        ("p_flags", c_uint),
        ("p_offset", c_ulonglong),
        ("p_vaddr", c_ulonglong),
        ("p_paddr", c_ulonglong),
        ("p_filesz", c_ulonglong),
        ("p_memsz", c_ulonglong),
        ("p_align", c_ulonglong)
    ]

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

descriptor: IO[bytes] = open("main", "rb")
buffer: bytes = descriptor.read()

descriptor.close()

header: ElfHeader = ElfHeader()
phdr: ElfPhdr = ElfPhdr()

memmove(addressof(header), buffer, sizeof(header))

print(buffer)

print(bytes(header.e_ident))