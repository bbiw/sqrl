from base64 import urlsafe_b64decode, urlsafe_b64encode

__all__ = ['onlydigits', 'encode', 'decode']

_identity = bytearray(range(256))
_digits = b'0123456789'
_notdigits = bytes(set(_identity) - set(_digits))
_b64u = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_'
_notb64u = bytes(set(_identity) - set(_b64u))
_PADDING = [b'', b'', b'==', b'=']


def onlydigits(b):
    '''return b with all non-digits removed'''
    return b.translate(_identity, _notdigits)


def clean_b64u(b):
    '''return b with all non-base64url characters removed'''
    return b.translate(_identity, _notb64u)


def decode(a):
    '''urlsafe_b64decode without padding'''
    a = a.translate(_identity, _notb64u)
    return urlsafe_b64decode(a + _PADDING[len(a) % 4])


def encode(b):
    '''urlsafe_b64encode without padding'''
    f = urlsafe_b64encode(b)
    l3 = len(b) % 3
    g = f if l3 == 0 else f[:l3 - 3]
    return g


if False:
    import string
    _ip6b85 = (string.digits + string.ascii_uppercase +
               string.ascii_lowercase + '!#$%&()*+-;<=>?@^_`{|}~').encode('ascii')
    _ip6a85 = bytearray(128)
    for i, c in enumerate(_ip6b85):
        _ip6a85[c] = i

    import math

    def b85enc(b):
        n = int.from_bytes(b, 'little')
        r = bytearray(math.ceil(len(b) * 5 / 4))
        for i in range(len(r) - 1, -1, -1):
            n, d = divmod(n, 85)
            r[i] = _ip6b85[d]
        return bytes(r)

    def b85dec(b):
        n = 0
        for c in b:
            n = n * 85 + _ip6a85[c]
        return n.to_bytes(math.ceil(len(b) * 4 / 5), 'little')
