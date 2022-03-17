# -*- encoding: utf-8 -*-
"""
keri.kli.common.existing module

"""

import getpass
import sys
from contextlib import contextmanager

from keri import kering
from keri.app import habbing, keeping


def setupHby(name, base="", bran=None, cf=None):
    """ Create Habery off of existing directory

    Parameters:
        name(str): name of habitat to create
        base(str): optional base directory prefix
        bran(str): optional passcode if the Habery was created encrypted
        cf (Configer): optional configuration for loading reference data

    Returns:
          Habery:  the configured habery

    """
    ks = keeping.Keeper(name=name,
                        base=base,
                        temp=False,
                        cf=cf,
                        reopen=True)
    aeid = ks.gbls.get('aeid')
    if aeid is None:
        print("Keystore must already exist, exiting")
        sys.exit(-1)

    ks.close()

    retries = 0
    while True:
        try:
            if bran:
                bran = bran.replace("-", "")

            retries += 1
            hby = habbing.Habery(name=name, base=base, bran=bran, cf=cf, free=True)
            break
        except (kering.AuthError, ValueError):
            if retries >= 3:
                raise kering.AuthError("too many attempts")
            print("Valid passcode required, try again...")
            bran = getpass.getpass("Passcode: ")
    return hby


@contextmanager
def existingHby(name, base="", bran=None):
    """
    Context manager wrapper for existing Habitat instance.
    Will raise exception if Habitat and database has not already been created.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        name(str): name of habitat to create
        base(str): optional base directory prefix
        bran(str): optional passcode if the Habery was created encrypted
    """
    hby = None
    try:
        hby = setupHby(name=name, base=base, bran=bran)
        yield hby

    finally:
        if hby:
            hby.close(clear=hby.temp)


@contextmanager
def existingHab(name, alias, base="", bran=None):
    """
    Context manager wrapper for existing Habitat instance.
    Will raise exception if Habitat and database has not already been created.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        name(str): name of habitat to create
        alias(str): alias for the identfier required
        base(str): optional base directory prefix
        bran(str): optional passcode if the Habery was created encrypted
    """
    with existingHby(name, base, bran) as hby:
        hab = hby.habByName(name=alias)
        yield hby, hab
