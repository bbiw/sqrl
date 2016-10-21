'''
This implentation is not threadsafe and not useful in a load-balanced environment.

However, a single server should handle the load for thousands of active clients.
'''
import struct
import time

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import namedtuple
import pysodium as na
import ctypes

from sqrl import KEY_BYTES, rng
from sqrl.crypto import Nonce, sha256sum


Nut = namedtuple("Nut", "now,up,ip,flags")


NUT_IPV6 = 1


class NutCase:
    '''

    To rotate keys, create a new instance, passing the old one as the first
    parameter. When all nuts issued under the old key expire, it will
    automatically be retired.

    new start:
        nc = NutCase()

    rotate:
        nc = NutCase(nc)

    restart:
        oldcase = pickle.dumps(nc)
        #ideally encrypt oldcase if you write it to non-volatile memory

        nc = NutCase(pickle.loads(oldcase))

    This implentation is not safe for unsynchronized use from multiple threads.

    '''
    NUTBOX = struct.Struct('>II4sH')

    def __init__(self, previous=None, timeout=300):
        '''create a nut generator

        previous: a previous instance that may have issued outstanding nuts
        start: the starting nonce
        timeout: maximum number of seconds a nut is valid for

        This instance generates a random key. Nuts sealed by other instances
        will not validate with this instance. (A server restart will invalidate
        all outstanding nuts unless this instance is pickled and restored.
        (Take care to not leak the key))
        '''
        self.old = previous
        self.start_now = int(time.time())
        self.start_up = int(time.monotonic())
        self.timeout = timeout
        self.__key = rng.randombytes(KEY_BYTES)
        self.nonce = Nonce()

    def new(self, ip, flags=0):
        '''create a nut based on the current time, prepared for a client at ip

        This implementation has room for 16 flag bits.
        '''
        if len(ip) > 4:
            ip = sha256sum(ip, 4)
            flags |= NUT_IPV6
        else:
            flags &= ~NUT_IPV6

        now = int(time.time())
        self._lastnow = now
        up = int(time.monotonic())
        nut = Nut(now, up, ip, flags)
        return nut

    def seal(self, nut):
        '''encrypt a nut and prepare for sending to a client
        '''
        message = self.NUTBOX.pack(*nut)
        nonce = next(self.nonce)
        box = nonce + na.crypto_secretbox(message, nonce, self.__key)
        return urlsafe_b64encode(box)

    def open(self, nut):
        '''decrypt and verify the integrity of a nut returned by a client

        returns the original nut passed to seal
        '''
        box = urlsafe_b64decode(nut)
        nonce = box[:na.crypto_secretbox_NONCEBYTES]
        ct = box[na.crypto_secretbox_NONCEBYTES:]
        pt = na.crypto_secretbox_open(ct, nonce, self.__key)
        return Nut(*self.NUTBOX.unpack(pt))

    def expired(self):
        '''return True if all issued nuts have expired'''
        now = int(time.time())
        then = self._lastnow + self.timeout
        return then < now

    def crack(self, ip, sealed):
        '''sanity check the values in the nut

        Because issued nuts are not stored by the server, we cannot prevent
        replay attacks at this point, but the timestamp limits the window
        of opportunity
        '''

        try:
            nut = self.open(sealed)
            # we are getting back new nuts, check to expire an old verifier
        except ValueError:
            if self.old:
                return self.old.crack(ip, sealed)
            else:
                raise

        if self.old and self.old.expired():
            self.old = None

        if len(ip) > 4:
            # IPV6 might give an attacker enough room to force a collision
            # of the first 4 bytes of a SHA2 hash
            ip = na.crypto_hash_sha256(ip)[4:]
            typematch = (nut.flags & NUT_IPV6) != 0
        else:
            typematch = (nut.flags & NUT_IPV6) == 0

        ipmatch = typematch and ip == nut.ip
        now = int(time.time())
        up = int(time.monotonic())
        goodtime = (nut.now >= self.start_now and now <= nut.now + self.timeout and
                    nut.now <= self._lastnow and
                    nut.up >= self.start_up and up <= nut.up + self.timeout)
        return nut, ipmatch, goodtime
