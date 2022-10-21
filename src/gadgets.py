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

from capstone import (
    Cs,
    CsInsn,
    CS_ARCH_X86,
    CS_MODE_64
)

from parser          import *
from collections.abc import Iterator


"""
-   src/gadgets.py
-   Date: 10/19/22
-   Author: @xmmword
"""


class GadgetScanner:
    def __init__(self, parser: ElfParser) -> None:
        """Initializes the ROP Gadget scanner.

        Args:
            parser (ElfParser): The instance of the 'ElfParser' class.
        """
        self._parser: ElfParser = parser

        self._text_section_header: ElfShdr = self._return_section_header(".text")
        self._text_section: Array[c_char] = create_string_buffer(self._text_section_header.sh_size)

        ElfParser._memcpy(
            self._text_section,
            self._parser._memory,
            self._text_section_header.sh_offset,
            self._text_section_header.sh_size
        )

        text_disassembly: list[CsInsn] = GadgetScanner.disassemble_bytes(self._text_section)

    def _gadget_scan() -> ...:
        ...

    def _return_section_header(self, section: str) -> ElfShdr | None:
        """Returns the section header corresponding to the name of the given section.

        Args:
            section (str): The name of the section.

        Returns:
            ElfShdr | None: The resolved section header, None will be returned if otherwise.
        """
        for i in range(self._parser.header.e_shnum):

            if (i + 1) < len(self._parser.section_header_table) and section in str(self._return_strtable_str(i)):
                return self._parser.section_header_table[i][1]

        return False

    def _return_strtable_str(self, index: int) -> bytes:
        """Returns a parsed string from a given string table index.

        Args:
            index (int): The string table index.

        Returns:
            bytes: The parsed string.
        """
        return self._parser.string_table[
               self._parser.section_header_table[index][1].sh_name:
               self._parser.section_header_table[index + 1][1].sh_name
        ]

    @staticmethod
    def disassemble_bytes(opcodes: bytes) -> list[CsInsn]:
        """Disassembles a given sequence of bytes.

        Args:
            opcodes (bytes): The sequence of bytes.

        Returns:
            list[CsInsn]: A list containing the disassembly data.
        """
        return [
            disassembly for disassembly in Cs(CS_ARCH_X86, CS_MODE_64).disasm(
                opcodes, 0x1000)
        ]