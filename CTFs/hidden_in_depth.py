# binary generated from python source code with PyInstaller
# pyinstxtractor 
# finds in the binary the compressed Python data and unpacks the Python bytecode files (.pyc)

# python3 pyinstxtractor.py hidden
# [+] Possible entry point: pyiboot01_bootstrap.pyc
# [+] Possible entry point: chall.pyc


# now i decompile chall.pyc
# decompyle3 /home/kali/Desktop/svt/CTFs/part1/hidden_extracted/chall.pyc > chall.py

key = [
 198,163,113,153,204,79,133,227,8,76,110,256,13,227,150,39,33,128,7,85,144,64,212,84,113,154,217,162,190,18,248,20,67,30,2,140,119,213,38,99,204,137,48,121,66,12,177,194,86]
enc_flag = [
 181,213,5,226,191,124,230,150,122,37,89,377,82,212,254,85,17,245,96,61,207,112,182,50,4,233,186,215,204,107,207,109,28,47,113,211,25,229,17,60,249,236,83,12,48,101,134,187,43]

flag = bytes(f ^ k for  f,k in zip(enc_flag, key))

print(flag.decode())