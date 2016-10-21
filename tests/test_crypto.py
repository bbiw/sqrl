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

NULLIV = b'\0' * 12

MINITER_INTERACTIVE = 20
MINTIME_INTERACTIVE = 2
MINITER_SENSITIVE = 100
MINTIME_SENSITIVE = 60
DEFAULT_LOGN = 9



def new_id():
    '''create a new identity'''
    rc = k.rescue_code()
    ilk, iuk = crypto_sign_keypair()
    imk = enhash(iuk)

    logN = DEFAULT_LOGN

    # block type 2
    access_salt = randbytes(16)
    miniter = MINITER_INTERACTIVE
    mintime = MINTIME_INTERACTIVE
    i, t, rescue_key = enscrypt(rc, rescue_salt, logN, miniter, mintime)
    access_nonce = randbytes(12)  # TODO: make this better
    ad = BLOCK1.pack(125, 1, 45, access_nonce, access_salt, logN,
                     i, optionflags, hintlength, pwverifysecs, idletimeoutmins)
    ct, tag = aes_gcm(access_key, access_nonce, imk + ilk, ad)

    block1 = ad + ct + tag

    # block type 2
    rescue_salt = randbytes(16)
    miniter = MINITER_SENSITIVE
    mintime = MINTIME_SENSITIVE
    i, t, rescue_key = enscrypt(rc, rescue_salt, logN, miniter, mintime)
    ad = BLOCK2.pack(73, 2, rescue_salt, logN, i)
    ct, tag = aes_gcm(rescue_key, NULLIV, iuk, ad)

    block2 = ad + ct + tag


def associate(imk,server):
    '''register with a new site'''
    spk,ssk = crypto_sign_seed_keypair(hmac(imk,server))
    suk, rlk = crypto_sign_keypair()
    vuk = crypto_sign_seed_keypair(crypto_scalarmult(ilk, rlk))[0]
    msg = sqrlchallenge
    sig = sign(msg,ssk)
def rekey(rc):
    '''replace exisiting identity'''

def reassociate(rc,server):
    '''tell server about new identity'''


def test_keygen():
    k = KeyGen('1337')


if __name__ == '__main__':
    test_enhash()
    test_enscrypt()
    test_enscrypt_time()
