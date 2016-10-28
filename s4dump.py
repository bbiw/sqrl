import os
from getpass import getpass

import click

import correcthorse

from sqrl import KEY_BYTES,rng
from sqrl.crypto import enhash
from sqrl.s4 import SQRLdata, Block, Access, Rescue, Previous
from sqrl.s4ext import Secret
from pysodium import crypto_sign_seed_keypair, crypto_sign_keypair

_wl = correcthorse.getwords(('effs1',))
def genpasswd():
    return correcthorse.random_passphrase(_wl)[0]

def gen_iuk():
    return crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))[1][:KEY_BYTES]

def getnewpassword(what):
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

    return pw

def getoldpassword(what):
    return getpass('enter {}'.format(what))

def rescue_code():
    '''generate a random password of 24 decimal digits'''
    return '-'.join(str(rng.randrange(10000)) for _ in range(6))


def createid(fname):
    click.echo('creating new id in "{}"'.format(fname))
    pw = getnewpassword('access password')

    rc = rescue_code()
    click.echo('Here is your emergency rescue code (write it in a secure place or memorize it):')
    click.echo(rc)
    ilk, iuk = crypto_sign_seed_keypair(rng.randombytes(KEY_BYTES))
    iuk = iuk[:KEY_BYTES]
    imk = enhash(iuk)

    click.echo('Encrypting your new identity. (This should take about 60 seconds.)')
    ab = Access().seal(imk + ilk, pw)
    rb = Rescue.seal(iuk, rc)
    sd = SQRLdata([ab,rb])
    with open(fname,'wb') as fo:
        sd.dump(fo)
    click.echo('Your new identity is now stored in "{}"'.format(os.path.abspath(fname)))



@click.command()
@click.argument('sqrldata')
def main(sqrldata):
    click.echo('hello')
    if os.path.exists(sqrldata):
        click.echo('found file "{}"'.format(sqrldata))
    else:
        createid(sqrldata)

if __name__ == '__main__':
    main()
