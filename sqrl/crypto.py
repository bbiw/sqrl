
from sqrl import KEY_BYTES
from pysodium import sodium
import ctypes


def enhash(data, iterations=16):
    assert len(data) == KEY_BYTES
    ld = ctypes.c_ulonglong(KEY_BYTES)
    u = ctypes.create_string_buffer(KEY_BYTES).raw
    sodium.crypto_hash_sha256(u, data, ld)
    acc = int.from_bytes(u, 'little')
    for i in range(1, iterations):
        sodium.crypto_hash_sha256(u, u, ld)
        acc ^= int.from_bytes(u, 'little')
    return acc.to_bytes(32, 'little')
