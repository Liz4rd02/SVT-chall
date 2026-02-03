import ctypes

# load shared library (C)
game_lib = ctypes.CDLL("CTFs/libgame.so")

flag_buffer = ctypes.create_string_buffer(100)

print("get_secured_string output:")

game_lib._Z18get_secured_stringPc(flag_buffer)

print(flag_buffer.value)


