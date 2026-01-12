import angr
import claripy
import sys

def main():
  path_to_binary = '/home/kali/Desktop/svt/Lab05/angr_symbolic_memory'
  project = angr.Project(path_to_binary)

  start_address = 0x080485fe #after the scanf
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 256)    #32 bytes, 256 bits
  ...

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)

  #is | grep user_input
  #56  ---------- 0x09413560 GLOBAL OBJ    33           user_input

  password0_address = 0x09413560
  initial_state.memory.store(password0_address, password0)
  ...

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

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=str
    # which returns a string instead of an integer.
    # (!)
    solution_bytes = solution_state.solver.eval(password0,cast_to=bytes)
    solution_string = solution_bytes.decode('latin-1')
    solution = solution_string[:8] + " " + solution_string[8:16] + " " + solution_string[16:24] + " " + solution_string[24:32]

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main()
