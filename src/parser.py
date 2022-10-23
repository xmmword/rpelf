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
    c_char,
    sizeof,
    memmove,
    addressof,
    create_string_buffer
)

from typing import (
    IO,
    TypeAlias
)

from object   import *
from capstone import CsInsn


"""
-   src/parser.py
-   Date: 10/22/22
-   Author: @xmmword
"""


Gadgets: TypeAlias = list[list[CsInsn]]

class ElfUtils:

    def _utils_filter_gadget(cache: list[CsInsn], gadget: list[CsInsn]) -> bool:
        """Filters repeated gadgets.

        Args:
            cache (list[CsInsn]): The previous gadget.
            instr (list[CsInsn]): The current gadget.

        Returns:
            bool: True if the gadget is a repeated gadget, False if otherwise.
        """
        for i in cache:

            repeated_gadgets: list[bool] = [
                True for k in gadget 
                    if not "ret" in k.mnemonic and k.address == i.address
            ] 

            if len(repeated_gadgets) > 0:
                return True

        return False

    def _utils_print_section_gadgets(section_gadgets: Gadgets) -> None:
        """Prints all of the discovered ROP gadgets.

        Args:
            section_gadgets (Gadgets): The gadgets discovered within the ELF section.
        """
        for gadgets in enumerate(section_gadgets):
            if not gadgets[1] or ((gadgets[0] - 1) > 0 and ElfUtils._utils_filter_gadget(
                        section_gadgets[gadgets[0] - 1], gadgets[1])):
                continue

            gadgets[1].reverse()
            gadgets[1].append(gadgets[1][0])

            del gadgets[1][0]

            print(f"Gadget @ [{hex(gadgets[1][0].address)}]")

            for instr in gadgets[1]:
                print(f"\t{hex(instr.address)}: {instr.mnemonic}\t{instr.op_str}")

            print()

    # Couldn't annotate with type[...] or 'GadgetScanner' due to issues with circular imports.
    def utils_print_gadgets(instance: object) -> None:
        """Prints the discovered gadgets in the .plt, .text, .init, and .fini ELF sections.

        Args:
            instance (object): The instance of the 'GadgetScanner' class.
        """
        ElfUtils._utils_print_section_gadgets(instance._plt_gadgets)
        ElfUtils._utils_print_section_gadgets(instance._text_gadgets)
        ElfUtils._utils_print_section_gadgets(instance._init_gadgets)
        ElfUtils._utils_print_section_gadgets(instance._fini_gadgets)

    def utils_print_header(instance: type['ElfParser']) -> None:
        """Prints the ELF header information.

        Args:
            instance (type['ElfParser']): The instance of the 'ElfParser' class.
        """
        print(
            "Executable Header Information:\n"
            f"\tMagic: {[hex(byte) for byte in bytes(instance.header.e_ident)]}\n"
            f"\tData: {instance.elf_return_endianness()}\n"
            f"\tVersion: {instance.elf_return_version()}\n"
            f"\tType: {instance.elf_return_type()}\n"
            f"\tEntry point: {hex(instance.header.e_entry)}\n"
            f"\tProgram Header Table offset: {hex(instance.header.e_phoff)}\n"
            f"\tSection Header Table offset: {hex(instance.header.e_shoff)}\n"
            f"\tProcessor Flags: {hex(instance.header.e_flags)}\n"
            f"\tELF Header size: {hex(instance.header.e_ehsize)}\n"
            f"\tProgram Header Table Entry Size: {hex(instance.header.e_phentsize)}\n"
            f"\tProgram Header Table Entries: {int(instance.header.e_phnum)}\n"
            f"\tSection Header Table Entry Size: {hex(instance.header.e_shentsize)}\n"
            f"\tSection Header Table Entries: {int(instance.header.e_shnum)}\n"
            f"\tString Table Index: {int(instance.header.e_shstrndx)}"
        "\n")

class ElfParser(ElfObject):

    def __init__(self, path: str) -> None:
        """Attempts to open a file descriptor to the ELF file, and validate the ELF header.

        Args:
            path (str): The path to the ELF file.
        """
        
        self.valid: bool
        self._path: str = path

        self._memory: bytes
        self._descriptor: IO[bytes] | None = self._elf_open()

        super().__init__()

        if not self._descriptor:
           return None

        self._memory = self._descriptor.read()
        self._elf_parse()

        self.valid = self._elf_checkheader()
        if not self.valid:
            return None

        self._descriptor.close()

        self.section_header_table = self.return_shdr_table((offset := self.header.e_shoff))
        self.string_table = self.return_str_table()

    def _elf_open(self) -> IO[bytes] | None:
        """Attempts to open the file and return a file descriptor.

        Returns:
            IO[bytes] | None: A file descriptor if the call to open() succeeded, None if otherwise.
        """
        try:
            return open(self._path, "rb")
        except:
            return None

    def _elf_checkheader(self) -> bool:
        """Checks the validity of the ELF header.

        Returns:
            bool: True if the ELF header is valid, False if otherwise.
        """
        return bool (
            (bytes(self.header.e_ident[:4]) == ElfConstants.ELF_MAGIC.value)
            and (bytes(self.header.e_ident[4]) == ElfConstants.ELF_CLASS64.value)
            and (bytes(self.header.e_machine) == ElfConstants.ELF_EM_X86_64.value)
        )

    def _elf_parse(self) -> None:
        """Parses core components of the ELF file."""
        ElfParser._memcpy(
            self.header, 
            self._memory,
            None,
            sizeof(self.header)
        )

        ElfParser._memcpy(
            self.section_header,
            self._memory, 
            self.header.e_phoff,
            sizeof(self.section_header)
        )

    def elf_return_type(self) -> str:
        """Parses and returns the type of ELF file.

        Returns:
            str: The type of ELF file.
        """
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
        """Parses and returns the ELF version.

        Returns:
            str: The ELF version.
        """
        match bytes(self.header.e_version):
            case ElfConstants.ELF_EV_NONE.value:
                return "Invalid version"
            case ElfConstants.ELF_EV_CURRENT.value:
                return "(1) Current version"
            case _:
                return "Invalid version"

    def elf_return_endianness(self) -> str:
        """Parses and returns the type of endianness.

        Returns:
            str: The type of endianness.
        """
        match bytes(self.header.e_ident[5]):
            case ElfConstants.ELF_DATANONE.value:
                return "Unknown data format"
            case ElfConstants.ELF_DATA2MSB.value:
                return "Two's complement, big-endian"
            case ElfConstants.ELF_DATA2LSB.value:
                return "Two's complement, little-endian"
            case _:
                return "Unknown data format"

    def return_str_table(self) -> Array[c_char]:
        """Returns the string table.

        Returns:
            Array[c_char]: The copied string table.
        """
        buffer: Array[c_char] = create_string_buffer(self.section_header_table[(self.header.e_shstrndx - 1)][1].sh_size)

        ElfParser._memcpy(
            buffer,
            self._memory,
            self.section_header_table[(self.header.e_shstrndx - 1)][1].sh_offset,
            self.section_header_table[(self.header.e_shstrndx - 1)][1].sh_size
        )

        return buffer

    def return_shdr_table(self, offset: int) -> tuple[tuple[int, ElfShdr]]:
        """Parses and returns a tuple representing the section header table.

        Args:
            offset (int): The offset of the first entry in the section header table.

        Returns:
            tuple[tuple[int, ElfPhdr]]: A tuple representing the section header table.
        """
        return tuple(
            (ElfParser._memcpy(entry, self._memory,
                (offset := offset + sizeof(entry)), sizeof(entry)), entry)
            for entry in (ElfShdr() for _ in range(self.header.e_shnum))
        )

    @staticmethod
    def _memcpy(dst: Any, src: Any, offset: int | None, count: int) -> int:
        """Copies bytes from one memory block to another.

        Args:
            dst (Any): The destination buffer.
            src (Any): The source buffer.
            offset (int): The source buffer offset.
            count (int): The amount of bytes to copy.

        Returns:
            int: The return value of memmove(dst, src, offset, count).
        """
        return memmove(addressof(dst), src[offset:], count)