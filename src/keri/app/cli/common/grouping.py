# -*- encoding: utf-8 -*-
"""
keri.kli.common.grouping module

"""


import blake3
from keri.core import coring


def extractDig(nexter, tholder):
    """
    Extracts the original digest of the public key from the digest created by XORing the
    key with the signing threshold.  This is used in group identifier event creation to enable
    creation of the next digest with the combined keys and the group signing threshold.

    Parameters:
        nexter is Nexter instance of next sith and next signing keys
        tholder is Tholder instance for event sith

    """
    dint = int.from_bytes(nexter.raw, 'big')

    limen = tholder.limen
    ldig = blake3.blake3(limen.encode("utf-8")).digest()
    sint = int.from_bytes(ldig, 'big')
    kint = sint ^ dint

    diger = coring.Diger(raw=kint.to_bytes(coring.Matter._rawSize(coring.MtrDex.Blake3_256), 'big'))
    return diger
