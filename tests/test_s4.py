from sqrl.s4 import *
from pysodium import crypto_sign_seed_keypair, crypto_sign_keypair

rc = b'0000-0000-0000-0000-0000-0000'
pw = b'monkey lipstick'
from sqrl import rng
rng.seed('1337')


def gen_iuk():
    return crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))[1][:KEY_BYTES]


def test_s4():

    ilk, iuk = crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))
    piuk = [gen_iuk(), gen_iuk(), gen_iuk()]

    iuk = iuk[:KEY_BYTES]
    rb = Rescue.seal(iuk, rc, 9, 1, .6)
    imk = enhash(iuk)
    ab = Access().seal(imk + ilk, pw)
    pb = Previous.seal(imk, piuk)
    s = SQRLdata([ab, rb, pb])

    sa = s.ascii()
    print(sa)
    source = io.BytesIO(sa.encode('ascii'))

    ab1, rb1, pb1 = SQRLdata.load(
        source, {0: Block, 1: Access, 2: Rescue, 3: Previous})
    print(ab1)
    print(rb1)
    print(pb1)

    iuk1 = rb1.open(rc)
    assert iuk == iuk1

    imk1, ilk1 = ab1.open(pw)
    assert ilk == ilk1
    assert imk == imk1

    piuk1 = pb1.open(imk)
    assert piuk == piuk1
if __name__ == '__main__':
    test_s4()
