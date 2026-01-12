import angr
import claripy
import sys

def angr_find_sol():
    path_to_binary = '/home/kali/Desktop/svt/exploits/recv_bin'
    #path_to_binary = '/home/kali/Desktop/svt/CTFs/part3/key_validator'
    project = angr.Project(path_to_binary, auto_load_libs=False)
    
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
    try:
        print(angr_find_sol())
    except Exception as e:
        print(e)

if __name__ == '__main__':
  main()