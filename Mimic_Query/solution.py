#!/usr/bin/env python
# coding: utf-8
from pwn import *
import re
from hashlib import sha256
import itertools
import string
import msg
from wolframclient.evaluation import WolframLanguageSession
from wolframclient.language import wl

sha_parse = re.compile(br"sha256\(XXXX ?\+ ?([^)]+).+ ([0-9a-z]+)", re.A)
ans_parse = re.compile(br"Answer: ?([A-Za-z]+)!", re.A)

mathematica = WolframLanguageSession("/opt/Wolfram/Mathematica/13.1/Executables/WolframKernel")

#context.log_level="DEBUG"

c = remote('nc.thuctf.redbud.info', port=31998)
powbanner = c.recvline()
#print(powbanner)
match = sha_parse.match(powbanner)
head, tail = match.group(1), match.group(2)
print("head = {}, tail = {}".format(head,tail))

for i in itertools.product(string.ascii_letters + string.digits + '!#$%&*-?', repeat=4):
    b = ''.join(i).encode("ASCII")
    digest = sha256(b + head).hexdigest()
    if digest.encode("ASCII") == tail:
        print("POW FOUND")
        break
c.sendline(b)

for _ in range(50):
    ans = []
    for i in range(15):
        c.recvuntil(b"Question: ")
        c.sendline(msg.query[i].encode("ASCII"))
        ans_l = c.recvline()
        ans_b = ans_parse.match(ans_l).group(1)
        ans.append(True if ans_b == b'True' else False)

    print(ans)
    corrected = mathematica.evaluate(wl.Nearest(msg.coded, ans, DistanceFunction=wl.HammingDistance))[0]
    print(corrected)
    send = b' '.join([b'1' if corrected[i] else b'0' for i in range(8)])
    c.recvuntil(b'Now open the chests:')
    c.sendline(send)

c.recvuntil(b"You've found all the treasure!")
print(c.recvline())

c.close()
mathematica.stop()
