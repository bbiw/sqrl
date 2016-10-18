from sqrl import KEY_BYTES
from sqrl.crypto import *

from base64 import urlsafe_b64decode

def test_enhash():
    with open('tests/enhash-vectors.txt') as fi:
        for line in fi:
            a = line[:43]+'='
            b = line[43:86]+'='
            key = urlsafe_b64decode(a)
            expected = urlsafe_b64decode(b)
            assert enhash(key)==expected

if __name__ == '__main__':
    test_enhash()
