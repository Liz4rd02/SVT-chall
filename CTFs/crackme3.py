import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13469


def main():
    server = remote(HOST, PORT)
    server.interactive()        #A1A1A1A11A1A1A1A, a1b2c3d44d3c2b1a ...

    #is_valid_serial(serial): 16 bytes, palyndrome, 1st char is vowel, LDLDLDLD...

if __name__ == '__main__':
    main()
