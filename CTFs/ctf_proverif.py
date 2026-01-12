import os
# Configure pwnlib environment
os.environ["PWNLIB_NOTERM"] = "True"
os.environ["PWNLIB_SILENT"] = "True"

from pwn import *
import hashlib
import time

# --- Configuration ---
context.log_level = "error" 

HOST = "svtctf.m0lecon.it"
PORT = 13415

# --- Cryptographic Helper Functions ---
sha256 = hashlib.sha256

def H(b: bytes) -> bytes:
    h = sha256()
    h.update(b)
    return h.digest()

def long_to_bytes(n: int) -> bytes:
    # Ensuring compatibility with standard libraries
    return n.to_bytes((n.bit_length() + 7) // 8, "big") or b"\x00"

# --- Leak Helper: Checks if A_PRIME is accepted ---
# --- Leak Helper: Checks if A_PRIME is accepted ---
def check_acceptance(A_PRIME: int) -> bool:
    """Sends A_PRIME and returns True if server proceeds to challenge prompt."""
    
    # Use a high timeout (5-10 seconds is good for stability)
    HIGH_TIMEOUT = 5 
    
    try:
        r = remote(HOST, PORT, timeout=HIGH_TIMEOUT)
        # 1. Read Server's B (Ignore value, just consume the output)
        r.recvuntil(b"Here is my public key: ")
        r.recvline() 
        r.recvuntil(b"Give me your public key: ")

        # 2. Send our A'
        r.sendline(str(A_PRIME).encode())
        
        # 3. Wait for acceptance prompt ('Give me the challenge (hex):')
        # If this times out, it throws an exception, meaning rejection.
        r.recvuntil(b"Give me the challenge (hex):", timeout=HIGH_TIMEOUT)
        
        # If we reach here, the key was accepted.
        r.close()
        return True
    
    except Exception:
        # This catches all Pwnlib timeouts, EOFs, or connection issues.
        # This means the key was rejected (or the server is very slow/down).
        if 'r' in locals() and r.connected:
            r.close()
        return False
# --- Optimized Modulus Leak Function (Multiples of B + Binary Search) ---

def find_modulus_p():
    print("="*50)
    print("🔍 Phase 1: Optimized Leak of Modulus 'p' (Multiples of B)")
    print("="*50)

    # 1. Get the server's public key (B)
    try:
        r = remote(HOST, PORT)
        #r.interactive()
        x = r.recvuntil(b"Here is my public key: ")
        print(x.decode(), end='') # Print "Here is my public key: "
        B_server_str = r.recvline().strip().decode()
        print(B_server_str) # Print B
        B_server_int = int(B_server_str)
        r.close()
    except Exception as e:
        print(f"[!] Failed to get initial B. Error: {e}")
        return None
    
    B = B_server_int
    print(f"Starting search for p near B (Magnitude: {len(B_server_str)} digits)")
    
    # 2. Bracketing Phase: Find A_rejected by sending multiples of B (3*B, 4*B, 5*B, ...)
    # Note: B itself is always accepted (since B = g^b mod p, B < p).
    
    A_lower = B 
    A_rejected = 0 
    
    multiplier = 2
    
    # Check multiples of B until rejection
    while True:
        A_PRIME = B * multiplier
        
        if check_acceptance(A_PRIME):
            A_lower = A_PRIME
            print(f"[+] Accepted A': {A_lower} ({multiplier} * B). Checking next multiple.")
            multiplier += 1
        else:
            # Rejection found! p is in the interval (A_lower, A_PRIME]
            A_rejected = A_PRIME
            print(f"Rejected A': {A_rejected} ({multiplier} * B). Modulus p is in: ({A_lower}, {A_rejected}]")
            break
        
        if multiplier > 100: # Safety break to prevent infinite looping in case of unexpected large p
            print("[!] Multiplier too large. Breaking bracketing phase.")
            return None

    # 3. Binary Search on the Interval (A_lower, A_rejected]
    # We maintain the property: check_acceptance(A_lower) is True, check_acceptance(A_rejected) is False
    
    #A_lower = 5270715533275169212738389050557175019453619105107475190155906911968729776347519067053581026173915669135714802739969967382161463195924591432285493687447124272692513419059309448077179312802744121179105946522900449503927382797145840429026976959867536180043789287554903791046713608701871452687812495670463777049379206069919550391026371182655757365528043879517828998939324811281460471318151472741282566442278795016375288343870787819924838484447328543086143785532502032751963732788313607514738100328281760149872726931421477113760178317789497659665098386691774578183171306152291478314017443838635067609074027330966106466932684309694509883157200496656026214720696912955094883141548777437615404579331234057029056651111141122038640602944702312186625076396591777196310666409269620918318937212322071599260069392852594561778578002155074804808139392741677871528182188754050986451910702464303369086175593277233631306760374489627720562052486
    #A_rejected = 5270716533275169212738389050557175019453619105107475190155906911968729776347519067053581026173915669135714802739969967382161463195924591432285493687447124272692513419059309448077179312802744121179105946522900449503927382797145840429026976959867536180043789287554903791046713608701871452687812495670463777049379206069919550391026371182655757365528043879517828998939324811281460471318151472741282566442278795016375288343870787819924838484447328543086143785532502032751963732788313607514738100328281760149872726931421477113760178317789497659665098386691774578183171306152291478314017443838635067609074027330966106466932684309694509883157200496656026214720696912955094883141548777437615404579331234057029056651111141122038640602944702312186625076396591777196310666409269620918318937212322071599260069392852594561778578002155074804808139392741677871528182188754050986451910702464303369086175593277233631306760374489627720562052486

    print(f"Switching to binary search. Interval: [{A_lower}, {A_rejected}]")
    
    # The true p is A_lower (the largest accepted) + 1.
    
    # The binary search starts one step higher than A_lower
    A_test = A_lower + 1
    
    while A_rejected - A_lower > 1:
        # Calculate the midpoint
        mid = (A_lower + A_rejected) // 2
        
        # We must ensure mid is always greater than A_lower
        if mid == A_lower:
             mid += 1
             if mid == A_rejected: break # Interval is [A_lower, A_rejected] size 1

        print(f"Testing midpoint: {mid}. Interval size: {A_rejected - A_lower}")
        
        if check_acceptance(mid):
            # Midpoint accepted -> p is in the upper half [mid, A_rejected]
            A_lower = mid
        else:
            # Midpoint rejected -> p is in the lower half [A_lower, mid]
            A_rejected = mid
        
    # When the loop terminates, A_rejected - A_lower == 1.
    # A_lower is the largest accepted value (p-1), and A_rejected is the first rejected value (p).
    p_modulus = A_rejected
    
    print(f"\n[!] Final Modulus p found: {p_modulus}")
    return p_modulus

# --- Main Execution ---

def main():
    # 1. FIND MODULUS P
    #p_modulus = find_modulus_p()
    p_modulus = 5270716116965698502689689671130781219142402682027195438035167686031865721400130496197382604002325978977917823871038888373085118354500422489134429970793096193438377786459821943518301475690713718745453633483219759953295608491564410082912515903134742148257215875373630412689071144760281744294536079770426517968527527493218935968663682019557492826204481612047410320146277333682801905360248457200458458982939490478875010628228329816347137904546340745621643293109290190631986349878770000332829974864263568375989597228583046155053640478805958492876860588535257030218304135983005840752161675722091031537527270835889607480661582626985375282908187505873350960702103509549729997875801557977556414403796543012974965425751833424162010931383924392626875437842811285456196644742198291857617009931030974156758885265756942730260677252867252555430773014258836269996233420470473918801854039549216620237517053340745984578639983387808534554731327
    if not p_modulus:
        print("\n[!] Could not determine modulus p. Exiting.")
        return

    # 2. PERFORM A = p-1 ATTACK
    
    print("\n" + "="*50)
    print(f"Phase 2: Attempting A = p-1 Attack with p = {p_modulus}")
    print("="*50)
    
    p_minus_1 = p_modulus - 1
    
    # Calculate the two possible shared secrets (k is 1 or p-1)
    k1_bytes = long_to_bytes(1)
    k2_bytes = long_to_bytes(p_minus_1)
    
    # s = H(k)
    s1 = H(k1_bytes)
    s2 = H(k2_bytes)
    
    # C = H(H(s))
    R1_HEX = H(s1).hex()
    R2_HEX = H(s2).hex()

    C1_HEX = H(H(s1)).hex()
    C2_HEX = H(H(s2)).hex()

    print(C1_HEX)
    print(C2_HEX)
   
    r = remote(HOST, PORT)
            
    # Read B and send A' = p-1
    #r.interactive()
    r.recvuntil(b"Here is my public key: ")
    r.recvuntil(b"Give me your public key: ")
    r.sendline(str(p_minus_1).encode())
    x = r.recvuntil(b"Here is your challenge: ", timeout=5)
    print(x)
    ch_hex = r.recvline().decode().strip()
    print(ch_hex)

    if(ch_hex == C1_HEX):
        rsp = R1_HEX
    elif(ch_hex == C2_HEX):
        rsp = R2_HEX
    else:
        print("Wrong modulus p")
        return
    
    r.recvuntil(b"Response? (hex): ", timeout=5)
    r.sendline(rsp.encode())
 
    out = r.recvall(timeout=3)
    print(out)
        


if __name__ == "__main__":
    main()