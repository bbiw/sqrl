from sqrl.s4 import *
from sqrl.s4ext import Secret
from pysodium import crypto_sign_seed_keypair, crypto_sign_keypair

rc = b'0000-0000-0000-0000-0000-0000'
pw = b'monkey lipstick'
from sqrl import rng
rng.seed('1337')


def gen_iuk():
    return crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))[1][:KEY_BYTES]

tm = dict((x.BLOCKTYPE, x) for x in (Block, Access, Rescue, Previous, Secret))


def genpasswd(len=16):
    return encode(rng.randombytes(len))


def test_s4():

    ilk, iuk = crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))
    piuk = [gen_iuk(), gen_iuk(), gen_iuk()]

    iuk = iuk[:KEY_BYTES]
    rb = Rescue.seal(iuk, rc, 9, 1, .6)
    imk = enhash(iuk)
    ab = Access().seal(imk + ilk, pw)
    pb = Previous.seal(imk, piuk)

    sitepw = genpasswd()
    sb = Secret.make(b'shop', b'amazon', b'terrel@gmail.com').seal(imk, sitepw)

    s = SQRLdata([ab, rb, pb, sb])

    sa = s.ascii()
    print(sa)
    source = io.BytesIO(sa.encode('ascii'))

    ab1, rb1, pb1, sb1 = SQRLdata.load(source, tm)
    print(ab1)
    print(rb1)
    print(pb1)
    print(sb1)

    iuk1 = rb1.open(rc)
    assert iuk == iuk1

    imk1, ilk1 = ab1.open(pw)
    assert ilk == ilk1
    assert imk == imk1

    piuk1 = pb1.open(imk)
    assert piuk == piuk1


if __name__ == '__main__':
    test_s4()
