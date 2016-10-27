from sqrl.s4 import *

rc = b'0000-0000-0000-0000-0000-0000'
pw = b'monkey lipstick'
from sqrl import rng
rng.seed('1337')


def test_s4():
    from pysodium import crypto_sign_seed_keypair
    ilk, iuk = crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))
    iuk = iuk[:KEY_BYTES]
    rb = Rescue.seal(iuk, rc, 9, 1, .6)
    imk = enhash(iuk)
    ab = Access().seal(imk + ilk, pw)
    s = SQRLdata([ab, rb])

    sa = s.ascii()
    print(sa)
    source = io.BytesIO(sa.encode('ascii'))

    ab1, rb1 = SQRLdata.load(source, {0: Block, 1: Access, 2: Rescue})
    print(ab1)
    print(rb1)

    iuk1 = rb1.open(rc)
    assert iuk == iuk1

    imk1, ilk1 = ab1.open(pw)
    assert ilk == ilk1
    assert imk == imk1

if __name__ == '__main__':
    test_s4()
