
KEY_BYTES = 32

import random,os
rng = random.SystemRandom()
rng.randombytes = os.urandom
