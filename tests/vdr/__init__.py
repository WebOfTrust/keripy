# -*- encoding: utf-8 -*-
"""
Test utilities for vdr
"""

from keri.core import Salter
from keri.kering import Vrsn_1_0, Kinds

from keri.app import habbing


def buildHab(db, ks, name="test", **kwa):
    """Utility to setup Habery and Hab for testing purposes
    Returns:
       tuple (Habery, Hab):
    """

    raw = b"raw salt to test"
    version = kwa.get("version", Vrsn_1_0)

    #  create secrecies
    secrecies = [[signer.qb64] for signer in
                 Salter(raw=raw).signers(count=8,
                                         path="name",
                                         temp=True)]

    # setup hab
    hby = habbing.Habery(name=name, temp=True, ks=ks, db=db, version=version)
    hab = hby.makeHab(name=name, secrecies=secrecies, **kwa)
    return (hby, hab)

