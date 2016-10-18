
from pysodium import sodium
import ctypes
def enhash(data, iterations=16):
    ld = ctypes.c_ulonglong(len(data))
    u = ctypes.create_string_buffer(32).raw
    sodium.crypto_hash_sha256(u,data,ld)
    ld = ctypes.c_ulonglong(32)
    acc = int.from_bytes(u,'little')
    for i in range(1, iterations):
        sodium.crypto_hash_sha256(u,u,ld)
        acc ^= int.from_bytes(u,'little')
    return acc.to_bytes(32,'little')
