import ctypes

# 1. Load the shared library
#CDLL because it's a C library
game_lib = ctypes.CDLL("CTFs/libgame.so")

# 2. Setup the argument type for get_secured_string
flag_buffer = ctypes.create_string_buffer(100)

# 3. Call the function
print("[*] Attempting to call get_secured_string...")
try:
    game_lib._Z18get_secured_stringPc(flag_buffer)
    
    print(f"Result: {flag_buffer.value.decode()}")
except Exception as e:
    print(f"Error: {e}")

