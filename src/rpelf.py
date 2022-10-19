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

from sys import (
    argv,
    exit
)

from parser import *
from colorama import Fore


"""
-   src/parser.py
-   Date: 10/19/22
-   Author: @xmmword
"""


def main(arguments: list[str]) -> None | NoReturn:
    exit(f"Usage: {arguments[0]} <elf-file>\n") if len(arguments) < 2 else ...

    elf: ElfParser = ElfParser(arguments[1])

    if not elf.valid:
        exit(f"{Fore.RED}Fatal Error{Fore.RESET}: The given file is either is not an elf file, or isn't a 64-bit executable!\n")

    print(
        "Executable Header Information:\n"
        f"\tMagic: {[hex(byte) for byte in bytes(elf.header.e_ident)]}\n"
        f"\tData: {elf.elf_return_endianness()}\n"
        f"\tVersion: {elf.elf_return_version()}\n"
        f"\tType: {elf.elf_return_type()}\n"
        f"\tEntry point: {hex(elf.header.e_entry)}\n"
        f"\tProgram Header Table offset: {hex(elf.header.e_phoff)}\n"
        f"\tSection Header Table offset: {hex(elf.header.e_shoff)}\n"
        f"\tProcessor Flags: {hex(elf.header.e_flags)}\n"
        f"\tELF Header size: {hex(elf.header.e_ehsize)}\n"
        f"\tProgram Header Table Entry Size: {hex(elf.header.e_phentsize)}\n"
        f"\tProgram Header Table Entries: {int(elf.header.e_phnum)}\n"
        f"\tSection Header Table Entry Size: {hex(elf.header.e_shentsize)}\n"
        f"\tSection Header Table Entries: {int(elf.header.e_shnum)}\n"
        f"\tString Table Index: {int(elf.header.e_shstrndx)}"
    "\n")

if __name__ == "__main__":
    main(argv)