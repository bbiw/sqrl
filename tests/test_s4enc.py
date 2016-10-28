
from sqrl.s4enc import *


def test_b64u():
    all = bytearray(range(256))
    all2 = all * 2
    t1 = encode(all)
    #print(len(t1) % 4, t1)
    assert decode(t1) == all

    t2 = encode(all2)
    #print(len(t2) % 4, t2)
    assert decode(t2) == all2

    #print()
    t3 = b' \n '.join(t2[i:i + 50] for i in range(0, len(t2), 50))
    #print(len(t3) % 4, t3.decode('ascii'))
    assert decode(t3) == all2

def test_all():
    import string
    all = (string.ascii_letters+string.digits+'-_').encode('ascii')*4
    t3 = b' \n '.join(all[i:i + 10] for i in range(0, len(all), 10))
    assert decode(all)==decode(t3)
    #print(t3.decode('ascii'))

if __name__ == '__main__':
    test_b64u()
    test_all()
