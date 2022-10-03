#!/usr/bin/env python
# coding: utf-8
from pwn import *
import re
from hashlib import sha256
import itertools
import string
from Crypto.Util.number import bytes_to_long

sha_parse = re.compile(br"sha256\(XXXX \+ ([^)]+).+ ([0-9a-z]+)", re.A)
sig_parse = re.compile(br"sig: (.*)", re.A)

#context.log_level="DEBUG"

c = remote('nc.thuctf.redbud.info', port=31712)
powbanner = c.recvline()
#print(powbanner)
match = sha_parse.match(powbanner)
head, tail = match.group(1), match.group(2)
print("head = {}, tail = {}".format(head,tail))

correct = b''
for i in itertools.product(string.ascii_letters + string.digits + '!#$%&*-?', repeat=4):
    b = ''.join(i).encode("ASCII")
    digest = sha256(b + head).hexdigest()
    if digest.encode("ASCII") == tail:
        correct = b
        print("POW FOUND")
        break
c.sendline(b)

def register(c, name):
    c.recvuntil(b'Choice:')
    c.sendline(b'1')
    c.recvuntil(b'Username:')
    c.sendline(name)

register(c, b'a-15852670688344')

c.recvuntil(b'Choice:')
c.sendline(b'4') # sell [2]
sigline = c.recvuntil(b'Price:')
c.sendline(b'100')
c.recvuntil(b'Flag:')
c.sendline(b'useless')

sig_am = sig_parse.search(sigline).group(1)
log.info('sig("a-15852670688344""5311") = {}'.format(sig_am))

register(c, b'a')

c.recvuntil(b'Choice:')
c.sendline(b'4') # sell [3]
sigline = c.recvuntil(b'Price:')
c.sendline(b'100')
c.recvuntil(b'Flag:')
c.sendline(b'useless')

c.recvuntil(b'Choice:')
c.sendline(b'6')
c.recvuntil(b'idx:')
c.sendline(b'3')
c.recvuntil(b'price:')
c.sendline(b'-158526706883445311')
c.recvuntil(b'sig:')
c.sendline(sig_am)

register(c, b'b')

c.recvuntil(b'Choice:')
c.sendline(b'5') # buy
c.recvuntil(b'idx:')
c.sendline(b'3')

c.recvuntil(b'Choice:')
c.sendline(b'5')
c.recvuntil(b'idx:')
c.sendline(b'0')

c.recvuntil(b'Choice:')
c.sendline(b'3')
c.recvuntil(b'idx:')
c.sendline(b'0')
c.recvuntil(b'sig:')
c.sendline(b'')
sigline = c.recvline()
sig = sig_parse.search(sigline).group(1)

c.recvuntil(b'Choice:')
c.sendline(b'3')
c.recvuntil(b'idx:')
c.sendline(b'0')
c.recvuntil(b'sig:')
c.sendline(sig)
c.recvline()
flag = c.recvline()

log.info(f"THUCTF{{{flag[:-1].decode('ASCII')}}}")

c.close()
