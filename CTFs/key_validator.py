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
PORT = 13473

def angr_find_sol(binary_data):
    #path_to_binary = '/home/kali/Desktop/svt/Lab05/angr_symbolic_registers'
    #binary_data = b"..."
    # Wrap bytes in BytesIO to simulate a file stream that angr loader can read.
    binary_stream = io.BytesIO(binary_data)

    project = angr.Project(binary_stream, auto_load_libs=False)

    
    obj = project.loader.main_object
    
    # 1. Get the real address of main
    main_addr = obj.get_symbol("main").rebased_addr

    off_from_main = 0x004012aa - 0x0040125f     #from first binary, structure is the same
    
    start_address = main_addr + off_from_main

    # 3. Create the state
    initial_state = project.factory.blank_state(addr=start_address)

    
    initial_state.regs.rsp = 0x7fffffff0000        # Give it a stack
    initial_state.regs.rbp = 0x7fffffff0000 + 0x100 

    # 5. Inject the key
    key = claripy.BVS('key', 16*8)    #16 bytes
    key_addr = obj.get_symbol('user_key').rebased_addr
    initial_state.memory.store(key_addr, key)

    key_bytes_in = key.chop(8)
    for b in key_bytes_in:
        initial_state.add_constraints(b != 10) # No Newline (\n)
        
    # 7. Explore
    simulation = project.factory.simgr(initial_state)

    offset_addr_to_check_constraint = 0x004012b4 - 0x0040125f
    address_to_check_constraint = main_addr + offset_addr_to_check_constraint   #after the transform function, before is_alnum
    simulation.explore(find=address_to_check_constraint)

    if simulation.found:
        solution_state = simulation.found[0]

        trans_key_addr = obj.get_symbol('transformed_key').rebased_addr
        trans_key = solution_state.memory.load(trans_key_addr, 16)    #load transformed key

        key_bytes = trans_key.chop(8)   ## Split the 16-byte key into a list of 16 1-byte chunks

        #add the constraint that transformed key must be alphanumeric (for each byte)
        for b in key_bytes:
            solution_state.add_constraints(
                claripy.Or(
                    claripy.And(b >= 0x30, b <= 0x39), # 0-9
                    claripy.And(b >= 0x41, b <= 0x5A), # A-Z
                    claripy.And(b >= 0x61, b <= 0x7A)  # a-z
                )
            )

        # Solve for the constrained_parameter_bitvector.

        solution_bytes = solution_state.solver.eval(key, cast_to=bytes)

        return(solution_bytes)
    else:
        raise Exception('Could not find the solution')


    
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
        print(server.recvuntil(b"Enter key: "))
        server.send(payload_bin)


    # read remainder of program output
    server.interactive()


if __name__ == '__main__':
  main()