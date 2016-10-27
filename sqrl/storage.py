import struct

from sqrl import rng
from collections import defaultdict, namedtuple


class Block:
    SINGLETON = False

    def __init__(self, bt=None, data=b''):
        self.bt = bt if bt is not None else self.BLOCKTYPE
        self.bdata = data
        self.offset = None
        self.dirty = True
        self.deleted = False

    def load(self, fo, offset, bl, bt, bh):
        self.bh = bh
        self.bt = bt  # preserve blocktype on save
        self.bdata = fo.read(bl - 4)
        self.offset = offset
        self.dirty = False
        self.deleted = False

    def dump(self, fo):
        self.offset = fo.tell()
        bl = len(self.bdata) + 4
        bt = self.bt or self.BLOCKTYPE
        self.bh = bh = struct.pack(">HH", bl, bt)
        fo.write(bh)
        fo.write(self.bdata)
        self.dirty = False


class Blocks(list):
    header = b'myblocks'

    def __init__(self, types):
        self.tm = tm = defaultdict(Block)
        for t, c in types:
            tm[t] = c
        self.by_type = defaultdict(list)

    def add_block(self, bt, block):
        self.append(block)
        if block.SINGLETON:
            old = self.by_type.get(bt)
            if old:
                old[0].deleted = True
        self.by_type[bt].append(block)

    def has_block(self, bt):
        return bt in self.by_type and len(self.by_type[bt] > 0)

    def get_blocks(self, bt):
        '''return all blocks of type bt'''
        return self.by_type[bt]

    def get_block(self, bt):
        '''return the newest block of type bt'''
        return self.by_type[bt][-1]

    def del_block(self, bt):
        '''remove the oldest block of type bt'''
        for b in self.by_type.get(bt, ()):
            if not b.deleted:
                b.deleted = True
                break

    def del_blocks(self, bt):
        '''remove all blocks of type bt'''
        for b in self.by_type.get(bt, ()):
            if not b.deleted:
                b.deleted = True

    def dump(self, fo):
        fo.write(self.header)
        for block in self:
            if not block.deleted:
                block.dump(fo)

    def load(self, fo):
        hh = fo.read(len(self.header))
        if hh != self.header:
            raise ValueError(
                'expected {}, got {} when reading header'.format(self.header, hh))
        while True:
            offset = fo.tell()
            bh = fo.read(4)
            if not bh:
                break
            bl, bt = struct.unpack('>HH', bh)
            block = self.tm[bt]()
            block.load(fo, offset, bl, bt, bh)
            self.add_block(bt, block)


NULLIV = b'\0' * 12

MINITER_INTERACTIVE = 20
MINTIME_INTERACTIVE = 2
MINITER_SENSITIVE = 100
MINTIME_SENSITIVE = 60
DEFAULT_LOGN = 9

class SQRLdata(Blocks):
    header = "sqrldata"
