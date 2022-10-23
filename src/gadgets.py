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
    CS_MODE_64,
    CS_ARCH_X86
)

from parser import *


"""
-   src/gadgets.py
-   Date: 10/22/22
-   Author: @xmmword
"""


GADGETS: tuple[str] = (
    "jo;",
    "je;",
    "jne;",
    "jmp;",
    "pop;",
    "push;",
    "syscall;",
    "add;ptr [",
    "mov;ptr ["
    "sal;ptr [",
)

class GadgetScanner:
    def __init__(self, parser: ElfParser) -> None:
        """Initializes the ROP Gadget scanner.

        Args:
            parser (ElfParser): The instance of the 'ElfParser' class.
        """
        self._parser: ElfParser = parser

        self._plt_gadgets: Gadgets = self._gadget_scan(
            self._return_section_disassembly(".plt"))
        
        self._text_gadgets: Gadgets = self._gadget_scan(
            self._return_section_disassembly(".text"))
        
        self._init_gadgets: Gadgets = self._gadget_scan(
            self._return_section_disassembly(".init"))
        
        self._fini_gadgets: Gadgets = self._gadget_scan(
            self._return_section_disassembly(".fini"))

    def _return_section_disassembly(self, section: str) -> tuple[CsInsn]:
        """Disassembles a given section.

        Args:
            section (str): The name of the section.

        Returns:
            tuple[CsInsn]: A tuple containing the disassembly of the given section.
        """
        section_header: ElfShdr = self._return_section_header(section)
        section_buffer: Array[c_char] = create_string_buffer(section_header.sh_size)
        
        ElfParser._memcpy(
            section_buffer,
            self._parser._memory,
            section_header.sh_offset,
            section_header.sh_size
        )

        return self._disassemble_bytes(section_buffer)

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

    def _collect_gadget_instr(self, index: int, disassembly: tuple[CsInsn]) -> list[CsInsn]:
        """Attempts to collect gadgets once a 'ret' instruction has been reached.

        Args:
            index (int): The index in the disassembly data where the 'ret' instruction is.
            disassembly (tuple[CsInsn]): A tuple containing disassembly data.

        Returns:
            list[CsInsn]: A list containing the instructions for the ROP gadget.
        """
        return [disassembly[(index - i)]
            for i in range(7) if (index - i) > 0 and self._check_gadget_instr(disassembly[(index - i)])
        ]

    def _gadget_scan(self, disassembly: tuple[CsInsn]) -> Gadgets:
        """Scans for ROP gadgets by iterating over a given tuple containing disassembly data.

        Args:
            disassembly (tuple[CsInsn]): A tuple containing disassembly data.

        Returns:
            Gadgets: A list of ROP gadgets.
        """
        gadgets: Gadgets = []
        
        for instr in enumerate(disassembly):
            if (instr[0] - 1) < 0 and self._check_gadget_instr(disassembly[(instr[0] - 1)]) is False:
                continue

            if "ret" in instr[1].mnemonic:
                gadget: list[CsInsn] = self._collect_gadget_instr(instr[0], disassembly)

                if len(gadget) > 0 and gadget[(len(gadget) - 1)].mnemonic != "ret":
                    gadget.append(instr[1])

                gadgets.append(gadget)

        return gadgets

    @staticmethod
    def _disassemble_bytes(opcodes: bytes) -> tuple[CsInsn]:
        """Disassembles a given sequence of bytes.

        Args:
            opcodes (bytes): The sequence of bytes.

        Returns:
            tuple[CsInsn]: A list containing the disassembly data.
        """
        return tuple(
            disassembly for disassembly in Cs(CS_ARCH_X86, CS_MODE_64).disasm(
                opcodes, 0x1000)
        )
    
    @staticmethod
    def _check_gadget_instr(instr: CsInsn) -> bool:
        """Checks if any mnemonic in 'GADGETS' matches with the disassembled instruction.

        Args:
            instr (CsInsn): The disassembled instruction.

        Returns:
            bool: True if the match was made, False if otherwise.
        """
        for mnemonic in GADGETS:

            if (mnemonic.split(";")[0] in instr.mnemonic
               and mnemonic.split(";")[1] in instr.op_str
             ) or mnemonic.split(";")[0] in instr.mnemonic:
                return True

        return False