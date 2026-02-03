from pwn import *

path = '/home/kali/Desktop/svt/CTFs/part1'
BINARY = os.path.join(path, 'slow')

elf = ELF(BINARY)

sleep_call_addr = 0x400d75  # identified with Ghidra

elf.write(sleep_call_addr, asm('nop') * 5)

patched_binary = os.path.join(path, 'slow_patched')
elf.save(patched_binary)

io = process(patched_binary)
output = io.recvall().decode()
print(output)
