import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13412


def make_payload():
    key = "5B134977135E7D13"

    payload = key.encode()

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
    out = server.recvall(timeout=1)
    print(out.decode())

if __name__ == '__main__':
    main()


