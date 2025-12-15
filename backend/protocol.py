import ctypes
import os

LIB_PATH = os.path.abspath("../build/libprotocol.so")
MAX_BUF = 256

lib = ctypes.CDLL(LIB_PATH)

# ---- function signatures ----
lib.serialize_connect_request.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8)
]
lib.serialize_connect_request.restype = ctypes.c_int

lib.serialize_scan_request.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8)
]
lib.serialize_scan_request.restype = ctypes.c_int

lib.deserialize_packet.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
    ctypes.c_void_p
]
lib.deserialize_packet.restype = ctypes.c_int
