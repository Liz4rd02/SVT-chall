import ctypes

# 1. Load the shared library
# We use CDLL because it's a C/C++ library
game_lib = ctypes.CDLL("CTFs/libgame.so")

# 2. Setup the argument type for get_secured_string
# It takes a char* (string pointer). We need to create a buffer for it to write into.
# Let's allocate a buffer of 100 bytes, filled with nulls.
flag_buffer = ctypes.create_string_buffer(100)

# 3. Call the function
# The symbol name is the mangled one you saw in r2: _Z18get_secured_stringPc
print("[*] Attempting to call get_secured_string...")
try:
    game_lib._Z18get_secured_stringPc(flag_buffer)
    
    # 4. Read the result
    print(f"[+] Result: {flag_buffer.value.decode('utf-8', errors='ignore')}")
except Exception as e:
    print(f"[-] Error calling function directly: {e}")

