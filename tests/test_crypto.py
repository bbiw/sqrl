from sqrl import KEY_BYTES
from sqrl.crypto import *

import os
import csv
from base64 import urlsafe_b64decode
from binascii import a2b_hex, b2a_hex

EXPENSIVE_TESTS = os.environ.get("EXPENSIVE_TESTS")


def test_enhash():
    with open('tests/enhash-vectors.txt') as fi:
        for line in fi:
            a = line[:43] + '='
            b = line[43:86] + '='
            key = urlsafe_b64decode(a)
            expected = urlsafe_b64decode(b)
            assert enhash(key) == expected


def test_enscrypt():
    '''this is a very time-consuming test (by design).'''

    with open('tests/enscrypt-vectors.csv') as fi:
        for row in csv.reader(fi):
            if not row:
                continue
            password, salt, logN, iterations, key = row
            i = int(iterations)
            if EXPENSIVE_TESTS or (i < 20):
                i, t, dkey = enscrypt(
                    password.encode('utf-8'),
                    a2b_hex(salt),
                    int(logN), i)
                print(row, i, t)
                assert b2a_hex(dkey).decode() == key


def test_enscrypt_time():
    i, t, dkey = enscrypt(b'', b'', 9, 1, 3)
    assert t >= 3
    assert i > 1


if __name__ == '__main__':
    test_enhash()
    test_enscrypt()
    test_enscrypt_time()
