# Angr doesn't currently support reading multiple things with scanf (Ex: 
# scanf("%u %u).) You will have to tell the simulation engine to begin the
# program after scanf is called and manually inject the symbols into registers.

import angr
import claripy
import sys

def main():
  path_to_binary = '/home/kali/Desktop/svt/Lab05/angr_symbolic_registers'
  project = angr.Project(path_to_binary)

  # Sometimes, you want to specify where the program should start. The variable
  # start_address will specify where the symbolic execution engine should begin.
  # Note that we are using blank_state, not entry_state.
  # (!)
  start_address = 0x080488b2   # :integer (probably hexadecimal)
  #after the get_user_input function. So i will just set the symbolic value instead
  initial_state = project.factory.blank_state(addr=start_address)

  # Create a symbolic bitvector (the datatype Angr uses to inject symbolic
  # values into the binary.) The first parameter is just a name Angr uses
  # to reference it. 
  # You will have to construct multiple bitvectors. Copy the two lines below
  # and change the variable names. To figure out how many (and of what size)
  # you need, dissassemble the binary and determine the format parameter passed
  # to scanf.
  # (!)
  password0_size_in_bits = 96  # :integer
  #because the receive user inputs function returns 3 registers of data, and each register is 4 bytes. So 12 bytes, or 96 bits.
  password0 = claripy.BVS('password0', password0_size_in_bits)
  ...

  # Set a register to a symbolic value. This is one way to inject symbols into
  # the program.
  # initial_state.regs stores a number of convenient attributes that reference
  # registers by name. For example, to set eax to password0, use:
  #
  # initial_state.regs.eax = password0
  #
  # You will have to set multiple registers to distinct bitvectors. Copy and
  # paste the line below and change the register. To determine which registers
  # to inject which symbol, dissassemble the binary and look at the instructions
  # immediately following the call to scanf.
  # (!)
  [bv_pw0, bv_pw1, bv_pw2] = password0.chop(32) #returns 3 smaller bv, each one of 32 bits
  initial_state.regs.eax = bv_pw0
  initial_state.regs.ebx = bv_pw1
  initial_state.regs.edx = bv_pw2

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Good Job." in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Try again." in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. If there are multiple solutions, we only
    # care about one, so we can use eval, which returns any (but only one)
    # solution. Pass eval the bitvector you want to solve for.
    # (!)
    solution_int = solution_state.solver.eval(password0)
    solution_bytes = solution_int.to_bytes(length=12, byteorder='big')

    # Aggregate and format the solutions you computed above, and then print
    # the full string. Pay attention to the order of the integers, and the
    # expected base (decimal, octal, hexadecimal, etc).
    #it expects 3 hex values, because the format string is "%x %x %x"
    bytes_eax = solution_bytes[0:4]
    bytes_ebx = solution_bytes[4:8]
    bytes_edx = solution_bytes[8:12]
    int_eax = int.from_bytes(bytes_eax, byteorder='big', signed=False) 
    int_ebx = int.from_bytes(bytes_ebx, byteorder='big', signed=False) 
    int_edx = int.from_bytes(bytes_edx, byteorder='big', signed=False)
    solution = hex(int_eax) + " " + hex(int_ebx) + " " + hex(int_edx)
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main()