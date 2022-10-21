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

from os       import path
from typing   import NoReturn
from colorama import Fore

from parser   import *
from gadgets  import *


"""
-   src/parser.py
-   Date: 10/19/22
-   Author: @xmmword
"""


def main(arguments: list[str]) -> None | NoReturn:
    exit("Usage: rpelf.py <elf-binary>\n") if len(arguments) < 2 else ...

    elf: ElfParser = ElfParser(arguments[1])

    if not path.exists(arguments[1]):
        exit(f"{Fore.RED}Fatal Error{Fore.RESET}: File '{arguments[1]}' doesn't exist!\n")

    if not elf.valid:
        exit(f"{Fore.RED}Fatal Error{Fore.RESET}: The given file is either isn't an ELF file, or isn't a 64-bit executable!\n")

    scanner: GadgetScanner = GadgetScanner(elf)

if __name__ == "__main__":
    main(argv)