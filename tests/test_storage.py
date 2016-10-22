import io

from sqrl import rng
from sqrl.storage import *


class MyBlock(Block):
    BLOCKTYPE = 13
    

class Singleton(MyBlock):
    BLOCKTYPE = 37
    SINGLETON = True


def test_add_block():
    mb = Blocks(((13,MyBlock),(37,Singleton)))
    b1 = MyBlock(13, rng.randombytes(214))
    mb.add_block(b1.bt, b1)
    s1 = Singleton(37, rng.randombytes(88))
    mb.add_block(s1.bt, s1)
    s2 = Singleton(37, rng.randombytes(88))
    mb.add_block(s2.bt, s2)
    b2 = MyBlock(13, rng.randombytes(214))
    mb.add_block(b2.bt, b2)

    assert s1.deleted
    assert not s2.deleted
    assert not b1.deleted
    assert not b2.deleted
    assert len(mb)==4

    fo = io.BytesIO()
    mb.dump(fo)

    fo.seek(0,0)
    rb = Blocks(((13,MyBlock),(37,Singleton)))
    rb.load(fo)

    s3 = rb.get_block(37)
    assert s3.bdata == s2.bdata
    b3,b4 = rb.get_blocks(13)
    assert b3.bdata == b1.bdata
    assert b4.bdata == b2.bdata
    assert len(rb)==3


if __name__ == '__main__':
    test_blocks()
