import hashlib

# Hash function (modify if needed)
def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def long_to_bytes(n: int) -> bytes:
    # built-in big-int → bytes
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\x00'

# ================================
#  SET YOUR CHALLENGE HERE
# ================================
ch_hex = "1b21136ae443d1144069e61de7e8d58052e0fdb3e921bd1e69ae5f073896aa62"
ch = bytes.fromhex(ch_hex)

print("[*] Starting brute-force search...")

# brute-force 32-bit exponent c
for c in range(0, 2**32):
    # compute k = 2^c
    k = 1 << c             # MUCH faster than pow(2, c)
    
    # compute s = H(long_to_bytes(k))
    s = H(long_to_bytes(k))

    # compute challenger-side H(H(s))
    test_ch = H(H(s))

    # check match
    if test_ch == ch:
        print(f"[+] FOUND c = {c}")
        # responder output: rsp = H(s)
        rsp = H(s)
        print(f"[+] rsp (hex) = {rsp.hex()}")
        break

else:
    print("[-] Exhausted 32-bit space - no match found.")
