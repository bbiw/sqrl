import os
from getpass import getpass

import click
import correcthorse
from cryptography.exceptions import InvalidTag

from sqrl import KEY_BYTES, rng
from sqrl.crypto import enhash
from sqrl.s4 import SQRLdata, Block, Access, Rescue, Previous
from sqrl.s4ext import Secret
from pysodium import crypto_sign_seed_keypair, crypto_sign_keypair

tm = dict((x.BLOCKTYPE, x) for x in (Block, Access, Rescue, Previous, Secret))

_wl = correcthorse.getwords(('effs1',))
_MRC = 1000000000000000000000000 # 24 zeros. (1e24 is off by 16777216)


def rescue_code():
    '''generate a random password of 24 decimal digits'''
    n = rng.randrange(_MRC)
    s = str(_MRC + n)[1:]
    return s.encode('ascii')


def genpasswd():
    '''generate a 90 bit diceware passphrase'''
    return correcthorse.random_passphrase(_wl)[0]


def gen_iuk():
    return crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))[1][:KEY_BYTES]


def getnewpassword(what):
    '''prompt the user for a new password'''
    click.echo('Here are some randomly selected words that you might use\n'
               '  (Each line has about 90 bits of entropy.):')
    for x in range(16):
        click.echo(genpasswd())
    click.echo()
    pw = getpass('enter {}:'.format(what))
    pw2 = getpass('reenter {}:'.format(what))
    while pw != pw2:
        click.echo('Passwords do not match. Please try again.')
        pw = getpass('enter {}:'.format(what))
        pw2 = getpass('reenter {}:'.format(what))

    return pw.encode('utf-8')


def getoldpassword(what):
    '''prompt the user for an existing password'''
    return getpass('enter {}'.format(what)).encode('utf-8')


def createid(fname):
    '''create a new SQRL identity, storing it to `fname`'''
    click.echo('creating new id in "{}"'.format(fname))
    pw = getnewpassword('access password')
    print(type(pw), pw)
    rc = rescue_code()
    click.echo(
        'Here is your emergency rescue code (write it in a secure place or memorize it):')
    urc = rc.decode('ascii')
    click.echo(' '.join(urc[i:i+4] for i in range(0,len(urc),4)))
    ilk, iuk = crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))
    iuk = iuk[:KEY_BYTES]
    imk = enhash(iuk)

    click.echo(
        'Encrypting your new identity. (This should take about 60 seconds.)')
    ab = Access().seal(imk + ilk, pw)
    rb = Rescue.seal(iuk, rc)
    sd = SQRLdata([ab, rb])
    with open(fname, 'wb') as fo:
        sd.dump(fo)
    click.echo('Your new identity is now stored in "{}"'.format(
        os.path.abspath(fname)))


def dumpid(fname, pw=None, rc=None):
    click.echo('dump of "{}"'.format(fname))
    print(type(pw), pw)
    print(type(rc), rc)
    with open(fname, 'rb') as fo:
        sd = SQRLdata(list(SQRLdata.load(fo, tm)))

    imk = None
    for b in sd:
        print(b)
        if isinstance(b, Access) and pw:
            try:
                imk, ilk = b.open(pw)
                print('IMK: {}\nILK: {}'.format(imk.hex(), ilk.hex()))
            except InvalidTag:
                print('invalid password or data corrupt')
        if isinstance(b, Rescue) and rc:
            try:
                iuk = b.open(rc)
                print('IUK: {}'.format(iuk.hex()))
            except InvalidTag:
                print('invalid password or data corrupt')
        if isinstance(b, Previous) and imk:
            try:
                puks = b.open(imk)
                for k in puks:
                    print('PIUK: {}'.format(k.hex()))
            except InvalidTag:
                print('invalid IMK or data corrupt')


@click.command()
@click.argument('sqrldata')
@click.option('--open', '-o', is_flag=True, help='prompt for passwords to decrypt blocks')
@click.option('--verbose', '-v', is_flag=True, help='display extra stuff')
@click.option('--config', '-c', help='read settings from CONFIG')
def main(sqrldata, open, verbose, config):
    click.echo('hello')
    if os.path.exists(sqrldata):
        if open:
            pw = getoldpassword('access key')
            if verbose and pw:
                click.echo(pw)
            rc = getoldpassword('rescue code')
            if verbose and rc:
                click.echo(rc)
        else:
            rc = pw = None

        dumpid(sqrldata, pw, rc)
    else:
        createid(sqrldata)

if __name__ == '__main__':
    main()
