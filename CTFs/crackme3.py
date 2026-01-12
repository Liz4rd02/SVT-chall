import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "svtctf.m0lecon.it" 
PORT = 13469


def main():
    server = remote(HOST, PORT)
    server.interactive()        #A1A1A1A11A1A1A1A

if __name__ == '__main__':
    main()
