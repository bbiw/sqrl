import io
import struct
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import namedtuple

from sqrl import TAG_BYTES, KEY_BYTES, NULLIV, rng
from sqrl.crypto import enscrypt, enhash, encrypt, decrypt

_PADDING = [b'', b'', b'==', b'=']


def decode(a):
    '''urlsafe_b64decode without padding'''
    return urlsafe_b64decode(a + _PADDING[len(a) % 4])


def encode(b):
    '''urlsafe_b64encode without padding'''
    f = urlsafe_b64encode(b)
    l3 = len(b) % 3
    g = f if l3 == 0 else f[:l3 - 3]
    return g


_aead = namedtuple('_aead', ('authdata', 'ciphertext', 'tag'))


class Block(namedtuple('Block', ('bocklen', 'blocktype', 'offset', 'data'))):
    '''preserve data for unrecognized block types'''
    __slots__ = ()

    @classmethod
    def for_bytes(cls, tc, data):
        bl = len(data) + 4
        return cls(bl, tc, None, struct.pack('<HH', bl, tc) + data)

    @classmethod
    def load(cls, blocklen, blocktype, source):
        offset = source.tell()
        data = source.read(blocklen)
        return cls(blocklen, blocktype, offset, data)

    def dump(self, sink):
        sink.write(self.data)


class EnScrypt(namedtuple('EnScrypt', 'salt,logN,iterations')):
    __slots__ = ()
    SALT_BYTES = 16
    DEFAULT_LOGN = 9
    MINITER_INTERACTIVE = 20
    MINTIME_INTERACTIVE = 2
    MINITER_SENSITIVE = 200
    MINTIME_SENSITIVE = 60
    _struct = struct.Struct('<{}sBI'.format(SALT_BYTES))

    def pack(self):
        return self._struct.pack(*self)

    @classmethod
    def unpack(cls, data):
        return cls(*cls._struct.unpack(data))

    @classmethod
    def randomsalt(cls):
        return rng.randombytes(cls.SALT_BYTES)

    def get_key(self, pw):
        return enscrypt(pw, self.salt, self.logN, self.iterations)[-1]

    @classmethod
    def new_key(cls, pw, logN, miniter, mintime):
        salt = cls.randomsalt()
        i, pt, dkey = enscrypt(pw, salt, logN, miniter, mintime)
        return cls(salt, logN, i), dkey

EnScrypt.DEFAULT = EnScrypt(None,
                            EnScrypt.DEFAULT_LOGN,
                            EnScrypt.MINITER_INTERACTIVE)


class Rescue:
    _struct = struct.Struct('<HH16sBI')
    _fields = ('blocklen', 'blocktype', 'salt', 'logN', 'iterations')
    __slots__ = _fields + ('aead',)
    BLOCKTYPE = 2
    BLOCKLEN = _struct.size + KEY_BYTES + TAG_BYTES

    def __init__(self, blocklen, blocktype, salt, logN, iterations):
        self.blocklen = blocklen
        self.blocktype = blocktype
        self.salt = salt
        self.logN = logN
        self.iterations = iterations
        self.aead = None

    @classmethod
    def load(cls, blocklen, blocktype, source):
        ad = source.read(cls._struct.size)
        ct = source.read(KEY_BYTES)
        tag = source.read(TAG_BYTES)
        that = cls(*cls._struct.unpack(ad))
        that.aead = _aead(ad, ct, tag)
        return that

    def dump(self, sink):
        ad, ct, tag = self.aead
        sink.write(ad)
        sink.write(ct)
        sink.write(tag)

    @classmethod
    def seal(cls, key, rescue_code,
             logN=EnScrypt.DEFAULT_LOGN,
             miniter=EnScrypt.MINITER_SENSITIVE,
             mintime=EnScrypt.MINTIME_SENSITIVE
             ):
        assert len(key) == KEY_BYTES
        assert len(rescue_code) >= 24
        sp, dkey = EnScrypt.new_key(rescue_code, logN, miniter, mintime)

        p = (cls.BLOCKLEN, cls.BLOCKTYPE) + sp
        that = cls(*p)
        ad = cls._struct.pack(*p)
        ct, tag = encrypt(dkey, NULLIV, key, ad)
        that.aead = _aead(ad, ct, tag)
        return that

    def get_key(self, rescue_code):
        return enscrypt(rescue_code, self.salt, self.logN, self.iterations)[-1]

    def open(self, rescue_code):
        dkey = self.get_key(rescue_code)
        ad, ct, tag = self.aead
        iuk = decrypt(dkey, NULLIV, ct, ad, tag)
        return iuk

    def __repr__(self):
        uid = self.aead.ciphertext.hex() if self.aead else 'None'
        return '<Rescue salt={} logN={} iterations={} uid={}>'.format(
            self.salt.hex(), self.logN, self.iterations,
            uid)


class Access:
    _fields = ('blocklen', 'blocktype', 'ptlen', 'gcmiv',
               'salt', 'logN', 'iterations',
               'optionflags', 'hintlen', 'pwverifysecs', 'idletimeoutmins')
    __slots__ = _fields + ('aead',)
    IV_BYTES = 12
    KEY_COUNT = 2
    _struct = struct.Struct(
        '<HHH{}s{}HBBH'.format(IV_BYTES, EnScrypt._struct.format[1:].decode('ascii')))
    PTLEN = _struct.size
    BLOCKTYPE = 1
    BLOCKLEN = PTLEN + KEY_BYTES * KEY_COUNT + TAG_BYTES

    def __init__(self, blocklen=BLOCKLEN, blocktype=BLOCKTYPE, ptlen=PTLEN, gcmiv=None,
                 salt=None, logN=9, iterations=None,
                 optionflags=0x1F, hintlen=6, pwverifysecs=1, idletimeoutmins=1):
        self.blocklen = blocklen
        self.blocktype = blocktype
        self.ptlen = ptlen
        self.gcmiv = gcmiv
        self.salt = salt
        self.logN = logN
        self.iterations = iterations
        self.optionflags = optionflags
        self.hintlen = hintlen
        self.pwverifysecs = pwverifysecs
        self.idletimeoutmins = idletimeoutmins

    @classmethod
    def load(cls, blocklen, blocktype, source):
        offset = source.tell()
        source.seek(4, 1)
        ptlen = int.from_bytes(source.read(2), 'little')
        assert ptlen == cls._struct.size
        source.seek(offset)
        ad = source.read(ptlen)
        that = cls(*cls._struct.unpack(ad))
        ctlen = cls.KEY_COUNT * KEY_BYTES
        ct = source.read(ctlen)
        tag = source.read(TAG_BYTES)
        that.aead = _aead(ad, ct, tag)
        return that

    def dump(self, sink):
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

    def scrypt_params(self):
        return EnScrypt(self.salt, self.logN, self.iterations)

    def get_key(self, pw):
        return enscrypt(pw, self.salt, self.logN, self.iterations)[-1]

    def seal(self, keys, password):
        assert len(keys) == self.KEY_COUNT * KEY_BYTES
        assert len(password) > 1

        sp, dkey = EnScrypt.new_key(
            password, self.logN, EnScrypt.MINITER_INTERACTIVE, self.pwverifysecs)
        self.salt, self.logN, self.iterations = sp
        return self._seal_with_key(keys, dkey)

    def _seal_with_key(self, keys, dkey):
        self.gcmiv = iv = self.next_nonce()
        ad = self._struct.pack(*(getattr(self, k) for k in self._fields))
        ct, tag = encrypt(dkey, iv, keys, ad)
        self.aead = _aead(ad, ct, tag)
        return self

    def open(self, password):
        assert len(password) > 1
        return self._open_with_key(self.get_key(password))

    def _open_with_key(self, dkey):
        iv = self.gcmiv
        ad, ct, tag = self.aead
        keys = decrypt(dkey, iv, ct, ad, tag)
        return tuple(keys[i:i + KEY_BYTES] for i in range(0, len(keys), KEY_BYTES))

    def __repr__(self):
        return '<Access iv={} salt={} logN={} iterations={} optionflags={} hintlen={} pwverifysecs={} idletimeoutmins={}>'.format(
            self.gcmiv.hex(), self.salt.hex(), self.logN, self.iterations,
            hex(self.optionflags), self.hintlen, self.pwverifysecs, self.idletimeoutmins)


class Previous:
    _fields = ('blocklen', 'blocktype', 'edition')
    __slots__ = _fields + ('aead',)
    _struct = struct.Struct('<HHH')
    PTLEN = _struct.size
    BLOCKTYPE = 3
    #BLOCKLEN = PTLEN + KEY_BYTES * KEY_COUNT + TAG_BYTES

    def __init__(self, blocklen, blocktype, edition):
        self.blocklen = blocklen
        self.blocktype = blocktype
        self.edition = edition

    @classmethod
    def load(cls, blocklen, blocktype, source):
        offset = source.tell()
        ad = source.read(cls.PTLEN)
        that = cls(*cls._struct.unpack(ad))
        ctlen = blocklen - cls.PTLEN - TAG_BYTES
        ct = source.read(ctlen)
        tag = source.read(TAG_BYTES)
        that.aead = _aead(ad, ct, tag)
        return that

    def dump(self, sink):
        ad, ct, tag = self.aead
        sink.write(ad)
        sink.write(ct)
        sink.write(tag)

    @classmethod
    def seal(cls, imk, keys, edition=None):
        if edition is None:
            edition = len(keys)
        blocklen = cls.PTLEN + TAG_BYTES + len(keys) * KEY_BYTES
        that = cls(blocklen, cls.BLOCKTYPE, edition)
        ad = cls._struct.pack(blocklen, cls.BLOCKTYPE, edition)
        ct, tag = encrypt(imk, NULLIV, b''.join(keys), ad)
        that.aead = _aead(ad, ct, tag)
        return that

    def open(self, imk):
        ad, ct, tag = self.aead
        keys = decrypt(imk, NULLIV, ct, ad, tag)
        return list(keys[i:i + KEY_BYTES] for i in range(0, len(keys), KEY_BYTES))

    def __repr__(self):
        count = len(self.aead.ciphertext)//KEY_BYTES
        return '<Previous edition={} keys={}>'.format(self.edition,count)


class SQRLdata(list):
    HEADER = b'sqrldata'
    ALT_HEADER = b'SQRLDATA'
    assert len(HEADER) == len(ALT_HEADER)

    def dump(self, sink):
        sink.write(self.HEADER)
        for x in self:
            x.dump(sink)

    def ascii(self):
        bio = io.BytesIO()
        self.dump(bio)
        bio.seek(len(self.HEADER))
        bin = bio.read()
        lp = 3 - (len(bin) % 3)
        return (self.ALT_HEADER + encode(bin)).decode('ascii')

    @classmethod
    def load(cls, source, typemap=None):
        if typemap is None:
            typemap = {0: Block}
        start = source.tell()
        header = source.read(len(cls.HEADER))
        if header == cls.ALT_HEADER:
            source = io.BytesIO(decode(source.read()))
        elif header != cls.HEADER:
            source.seek(start)
            raise ValueError('bad header: expecting {} or {}. got {}'.format(
                cls.HEADER, cls.ALT_HEADER, header
            ))

        while True:
            offset = source.tell()
            bhead = source.read(4)
            if not bhead:
                break
            source.seek(offset)
            blocklen, blocktype = struct.unpack('<HH', bhead)
            breader = typemap.get(blocktype) or typemap[0]
            yield breader.load(blocklen, blocktype, source)
