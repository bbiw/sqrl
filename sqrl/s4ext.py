'''
blocklen    2
blocktype   2
ptlen       2
gcmiv      12
modtime     4  seconds since epoch (2016-10-16)
path        1...   length byte, utf-8 string
realm       1...
username    1...
encrypted data
authtag
'''
import time
import struct
from hashlib import sha256

from sqrl.s4 import _aead
from sqrl import rng, TAG_BYTES
from sqrl.crypto import enhash, encrypt, decrypt


def read_pstr(source, maxlen):
    b = ord(source.read(1))
    if b > maxlen:
        raise ValueError('string too long: len={} maxlen={}'.format(b, maxlen))
    return maxlen - b - 1, source.read(b)


def write_pstrs(sink, *strs):
    for s in strs:
        l = len(s)
        assert l < 256
        sink.write(l.to_bytes(1, 'little'))
        sink.write(s)


class Secret:
    _fields = ('blocklen', 'blocktype', 'ptlen', 'gcmiv',
               'modtime', 'path', 'realm', 'username')
    __slots__ = _fields + ('aead', 'authenticated')
    BLOCKTYPE = 129
    IV_BYTES = 12
    _struct = struct.Struct('<HHH{}sI'.format(IV_BYTES))
    FIXED_BYTES = _struct.size

    def __init__(self, blocklen, blocktype, ptlen, gcmiv,
                 modtime, path, realm, username):
        self.blocklen = blocklen
        self.blocktype = blocktype
        self.ptlen = ptlen
        self.gcmiv = gcmiv
        self.modtime = modtime
        self.path = path
        self.realm = realm
        self.username = username
        self.authenticated = False

    @classmethod
    def make(cls, path=b'', realm=b'', username=b''):
        ptlen = cls.FIXED_BYTES + 3 + len(path) + len(realm) + len(username)
        blocklen = ptlen + TAG_BYTES
        return cls(blocklen, cls.BLOCKTYPE, ptlen, None, None, path, realm, username)

    @classmethod
    def load(cls, blocklen, blocktype, source):
        offset = source.tell()
        bl, bt, ptlen, gcmiv, modtime = cls._struct.unpack(
            source.read(cls.FIXED_BYTES))
        ctlen = blocklen - ptlen - TAG_BYTES
        if ctlen < 0:
            # XXX: this will leave the source stream in an undefined state
            raise ValueError(
                'corrupt header field: ptlen={} blocklen={}'.format(ptlen, blocklen))
        path = realm = username = b''
        maxlen = ptlen - cls.FIXED_BYTES
        if maxlen > 0:
            maxlen, path = read_pstr(source, maxlen)
        if maxlen > 0:
            maxlen, realm = read_pstr(source, maxlen)
        if maxlen > 0:
            maxlen, username = read_pstr(source, maxlen)
        source.seek(offset)

        that = cls(bl, bt, ptlen, gcmiv, modtime, path, realm, username)
        ad = source.read(ptlen)
        ct = source.read(ctlen)
        tag = source.read(TAG_BYTES)
        that.aead = _aead(ad, ct, tag)
        that.authenticated = False
        return that

    def get_key(self, imk):
        '''get secret encryption key'''
        h = sha256(imk)
        for x in self.path, self.realm, self.username:
            h.update(len(x).to_bytes(1,'little'))
            h.update(x)
        return enhash(h.digest())

    def seal(self, imk, secret):
        dkey = self.get_key(imk)
        return self._seal_with_key(dkey, secret)

    def _seal_with_key(self, dkey, secret):
        iv = self.gcmiv = self.next_nonce()
        bl = 3 + len(self.path) + len(self.realm) + len(self.username)
        ba = bytearray(bl)
        i = 0
        for s in self.path, self.realm, self.username:
            l = len(s)
            ba[i] = l
            i += 1
            for x in s:
                ba[i] = x
                i += 1
        adlen = self.ptlen = self.FIXED_BYTES + bl
        self.blocklen = adlen + TAG_BYTES + len(secret)
        self.modtime = int(time.time())
        ad = self._struct.pack(self.blocklen, self.blocktype,
                               adlen, iv, self.modtime) + ba
        ct, tag = encrypt(dkey, iv, secret, ad)
        self.aead = _aead(ad, ct, tag)
        self.authenticated = True
        return self

    def open(self, imk):
        dkey = self.get_key(imk)
        return self._open_with_key(dkey)

    def _open_with_key(self, dkey):
        iv = self.gcmiv
        ad, ct, tag = self.aead
        secret = decrypt(dkey, iv, ct, ad, tag)
        self.authenticated = True
        return secret

    def dump(self, sink):
        assert self.authenticated
        ad, ct, tag = self.aead
        sink.write(ad)
        sink.write(ct)
        sink.write(tag)

    def next_nonce(self):
        iv = self.gcmiv
        ivl = self.IV_BYTES
        if iv:
            # XXX is this safe?
            nn = sha256sum(iv, ivl * 2)
            d0 = int.from_bytes(nn[:ivl], 'little')
            d1 = int.from_bytes(nn[ivl:], 'little')
            return (d0 ^ d1).to_bytes(ivl, 'little')

        return rng.randombytes(ivl)

    def __repr__(self):
        return '<Secret path={} realm={} username={} secret={}>'.format(
            self.path.decode('utf-8'),
            self.realm.decode('utf-8'),
            self.username.decode('utf-8'),
            self.aead.ciphertext.hex()
        )
