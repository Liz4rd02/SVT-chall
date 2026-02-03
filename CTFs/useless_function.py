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
PORT = 13420

def angr_find_sol(binary_data):
    #path_to_binary = '/home/kali/Desktop/svt/Lab05/angr_symbolic_registers'
    #binary_data = b"..."
    # Wrap bytes in BytesIO to simulate a file stream that angr loader can read.
    binary_stream = io.BytesIO(binary_data)

    project = angr.Project(binary_stream, auto_load_libs=False)

    
    obj = project.loader.main_object
    
  
    main_addr = obj.get_symbol("main").rebased_addr

    off_from_main = 75
    
    start_address = main_addr + off_from_main


    initial_state = project.factory.blank_state(addr=start_address)

    
    initial_state.regs.rsp = 0x7fffffff0000        # Give it a stack
    initial_state.regs.rbp = 0x7fffffff0000 + 0x100 

    key = claripy.BVS('key', 16*8)    
    key_addr = obj.get_symbol('user_key').rebased_addr
    initial_state.memory.store(key_addr, key)

    # 6. Hook useless_function
    useless_addr = obj.get_symbol('useless_function').rebased_addr
    project.hook(useless_addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

    # 7. Explore
    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b"Correct!" in stdout_output

    def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b"Wrong" in stdout_output

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution_state = simulation.found[0]
        solution_bytes = solution_state.solver.eval(key, cast_to=bytes)
        return solution_bytes
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