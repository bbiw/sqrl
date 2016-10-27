
import random
import os
if False:
    rng = random.SystemRandom()
    rng.randombytes = os.urandom
else:
    class MyRandom:
        '''a swappable random number generator'''
        rng = None

        def seed(self, seed=None):
            old = getattr(self, 'rng', None)
            if seed is None:
                if isinstance(old, random.SystemRandom):
                    return
                rng = random.SystemRandom()
            else:
                if not isinstance(old, random.SystemRandom):
                    old.seed(seed)
                    return
                rng = random.Random(seed)

            if old is not None:
                for k, v in old.__dict__.items():
                    if v and v.__self__ == old:
                        setattr(self, k, getattr(rng,k))
            self.rng = rng

        __init__ = seed

        def randombytes(self, count):
            return self.rng.getrandbits(count * 8).to_bytes(count, 'little')

        def __getattr__(self, key):
            value = getattr(self.rng, key)
            setattr(self, key, value)
            return value

    rng = MyRandom()

# AES-GCM Parameters
KEY_BYTES = 32
TAG_BYTES = 16
GCMIV_BYTES = 12
NULLIV = b'\0' * GCMIV_BYTES


# EnScrypt Parameters
SCRYPT_SALT_BYTES = 16
DEFAULT_LOGN = 9
MINITER_INTERACTIVE = 20
MINTIME_INTERACTIVE = 2
MINITER_SENSITIVE = 100
MINTIME_SENSITIVE = 60
