from pwn import *
import os, sys

path = '/home/kali/Desktop/svt/CTFs/part1'
BINARY = os.path.join(path, 'encryption-1')

def make_payload(target_elf):
    flag_addr = 0x404030

    flag_length = 22 
    payload = target_elf.read(flag_addr, flag_length)
    
    return payload

def main():

    elf = ELF(BINARY)

    flag_addr = 0x404030    #flag: glob var in .data
    flag_length = 22 
    flag = elf.read(flag_addr, flag_length)

    print(flag.decode())

    #io = process([BINARY, flag])
    #out = io.recvall()
    #print(out.decode())

if __name__ == '__main__':
    main()