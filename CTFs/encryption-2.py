enc_flag = b"14691s/2.q\035q,!0;26sr,\0351!*q/v?"   #xored flag at 0x404030
key = 0x42

flag = bytes(b ^ key for b in enc_flag)

print(flag)

