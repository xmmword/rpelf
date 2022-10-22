# rpelf
A 64-bit ELF ROP gadget finder written in Python. 

<div align="center">
    <img src="https://user-images.githubusercontent.com/105472509/197366603-0a5e60a5-c2d3-42c3-b52c-0f4c8bfa0b0e.png" width="700px"><br>
</div>

## Description
`rpelf` is a tool written in Python that searches for ROP gadgets within a given 64-bit ELF executable. It accomplishes this via parsing the given ELF file's
header and section header table, reading the bytes of the `.plt`, `.text`, `.init`, and `.fini` into a buffer, disassembling the bytes stored in the buffer,
and then reading the disassembly data to search for possible ROP, JOP, and SYS gadgets.

### Features
- Fast
- Filters inaccurate results
- Searches for ROP, JOP, and SYS gadgets

### Built with
- Python (3.10.6)

## Getting started
### Usage
- `python3 rpelf.py <binary>`

## Credits
```
https://github.com/xmmword
```
### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.
