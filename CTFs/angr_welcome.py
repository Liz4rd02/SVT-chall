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
PORT = 13441

def angr_find_sol(binary_data):
    #path_to_binary = '/home/kali/Desktop/svt/Lab05/angr_symbolic_registers'
    #binary_data = b"..."
    # Wrap bytes in BytesIO to simulate a file stream that angr loader can read.
    binary_stream = io.BytesIO(binary_data)

    project = angr.Project(binary_stream, auto_load_libs=False)

    
    obj = project.loader.main_object
    base = obj.mapped_base  #addr where mapped in memory
    #start_offset = 0x004011cd - 0x00400000  #from the first binary, structure is the same

    #start_address = base + start_offset #after fread and first check on input length
    #initial_state = project.factory.blank_state(addr=start_address)

    key_check_offset = 0x004011b0 - 0x00400000  #offset of instruction where he checks the key length, to extract it
    key_check_addr = base + key_check_offset

    block = project.factory.block(key_check_addr, size=16)

    for insn in block.capstone.insns:
        if insn.address == key_check_addr and insn.mnemonic == "cmp":
            key_size = insn.op_str.split(",")[1].strip()
            key_size = int(key_size, 16)
            #print("Key length found: " + str(key_size))
            break
        else:
            raise Exception("Key length instruction not found")


    key = claripy.BVS('key', key_size*8)   
    
    stdin = SimFileStream(
        name="stdin",
        content=key,
        has_end=False
    )


    initial_state = project.factory.entry_state(
        stdin=stdin
    )
 

    #key_addr = initial_state.regs.rbp - 0x1a

    #initial_state.memory.store(key_addr, key)
    
    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b"OK" in stdout_output 

    def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b"Invalid key" in stdout_output

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution_state = simulation.found[0]
        solution_bytes = solution_state.solver.eval(key,cast_to=bytes)
        return solution_bytes
        #print(solution)
    else:
        raise Exception('Could not find the solution')

    
def main():
    server = remote(HOST, PORT)
    #server.interactive()
    #server.recvuntil(b">")
    #server.sendline(b"0")

    for i in range (0,30):
        a = server.recvuntil(b"-----BEGIN BINARY-----\n", timeout=5)
        print(a)
        b64_bin = server.recvuntil(b"\n").strip().decode()
        bin = base64.b64decode(b64_bin)

        #print(b64_bin)
        with open("recv_bin", "wb") as f:
            f.write(bin)

        payload_bin = angr_find_sol(bin)
        print(f"Sending payload {payload_bin} of length {len(payload_bin)}")
        b = server.recvuntil(b"Enter the key: ")
        print(b)
        server.send(payload_bin)
        #server.interactive()


    # read remainder of program output
    server.interactive()


if __name__ == '__main__':
  main()