enc_flag = b"14691s/2.q\035q,!0;26sr,\0351!*q/v?"
key = b'B'  # XOR key

key_val = key[0]   # convert b'A' → 65

flag = ""

for c in enc_flag:
    flag += chr(c ^ key_val)

print(flag)
