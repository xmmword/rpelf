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

from object import *
from typing import *


"""
-   src/parser.py
-   Date: 10/19/22
-   Author: @xmmword
"""


class ElfParser(ElfObject):

    def __init__(self, path: str) -> None:
        self.valid: bool
        self._path: str = path
        self._descriptor: IO[bytes] | None = self._elf_open()

        super().__init__()

        if not self._descriptor:
            return None

        self._descriptor.readinto(self.header)

        self.valid = self._elf_checkheader()
        if not self.valid:
            return None

        self._descriptor.close()

    def _elf_open(self) -> IO[bytes] | None:
        try:
            return open(self._path, "rb")
        except:
            return None

    def _elf_checkheader(self) -> bool:
        return bool(
            (bytes(self.header.e_ident[:4]) == ElfConstants.ELF_MAGIC.value)
            and (bytes(self.header.e_ident[4]) == ElfConstants.ELF_CLASS64.value)
            and (bytes(self.header.e_machine) == ElfConstants.ELF_EM_X86_64.value)
        )

    def _elf_parse(self):
        
        return True

    def elf_return_type(self) -> str:
        match bytes(self.header.e_type):
            case ElfConstants.ELF_ET_DYN.value:
                return "Position-Independent Executable file"
            case ElfConstants.ELF_ET_REL.value:
                return "Relocatable file"
            case ElfConstants.ELF_ET_NONE.value:
                return "Unknown type"
            case ElfConstants.ELF_ET_EXEC.value:
                return "Executable file"
            case ElfConstants.ELF_ET_CORE.value:
                return "Core file"
            case _:
                return "Unknown type"

    def elf_return_version(self) -> str:
        match bytes(self.header.e_version):
            case ElfConstants.ELF_EV_NONE.value:
                return "Invalid version"
            case ElfConstants.ELF_EV_CURRENT.value:
                return "(1) Current version"
            case _:
                return "Invalid version"

    def elf_return_endianness(self) -> str:
        match bytes(self.header.e_ident[5]):
            case ElfConstants.ELF_DATANONE.value:
                return "Unknown data format"
            case ElfConstants.ELF_DATA2MSB.value:
                return "Two's complement, big-endian"
            case ElfConstants.ELF_DATA2LSB.value:
                return "Two's complement, little-endian"
            case _:
                return "Unknown data format"