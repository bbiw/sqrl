
import sqrl.server
from sqrl.server import *

import time
import pickle


class MockTime:
    def __init__(self):
        self._now = time.time()
        self._mo = time.monotonic() - self._now

    def tick(self,seconds):
        self._now+=seconds

    def time(self):
        return self._now

    def monotonic(self):
        return self._now+self._mo


def test_rotate():
    ft = sqrl.server.time = MockTime()

    nc = NutCase()

    ip = bytearray((192, 168, 0, 100))
    ip2 = bytearray((192, 168, 0, 200))

    n1 = nc.new(ip)
    s1 = nc.seal(n1)
    ft.tick(160)

    nc = NutCase(nc)
    assert not nc.old.expired()

    n2 = nc.new(ip2)
    s2 = nc.seal(n2)

    nn,ipm,gt = nc.crack(ip,s1)
    assert n1 == nn

    ft.tick(160)
    assert nc.old.expired()


    nn,ipm,gt = nc.crack(ip2,s2)
    assert n2 == nn
    assert nc.old is None

    try:
        nn,ipm,gt = nc.crack(ip,s1)
        assert False
    except ValueError:
        pass


def test_nut():
    ft = sqrl.server.time = MockTime()
    nc = NutCase()
    ip = bytearray((192, 168, 0, 100))
    ip2 = bytearray((192, 168, 0, 200))

    print(ft._now)
    n0 = nc.new(ip)
    ft.tick(300)
    print(ft._now)
    n1 = nc.new(ip)
    ft.tick(200)
    print(ft._now)
    n2 = nc.new(ip)
    print(n0)
    print(n1)
    print(n2)
    s0 = nc.seal(n0)
    s1 = nc.seal(n1)
    s2 = nc.seal(n2)

    nn,ipm,gt = nc.crack(ip,s0)
    assert n0 == nn
    assert ipm
    assert not gt

    nn,ipm,gt = nc.crack(ip,s1)
    assert n1 == nn
    assert ipm
    assert gt

    nn,ipm,gt = nc.crack(ip2,s1)
    assert n1 == nn
    assert not ipm
    assert gt

    nn,ipm,gt = nc.crack(ip,s2)
    assert n2 == nn
    assert ipm
    assert gt

    ft.tick(301)
    nn,ipm,gt = nc.crack(ip,s2)
    assert n2 == nn
    assert ipm
    assert not gt


def test_nonce():
    n = Nonce()
    p = pickle.dumps(n)

    n1 = [next(n) for _ in range(20)]

    n = pickle.loads(p)

    n2 = [next(n) for _ in range(20)]
    assert n1 == n2

if __name__ == '__main__':
    test_rotate()
