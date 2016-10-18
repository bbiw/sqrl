from sqrl import KEY_BYTES
from sqrl.crypto import *

def test_enhash():
    h = enhash(b'\0'*KEY_BYTES)
    print(h)


if __name__ == '__main__':
    test_enhash()
