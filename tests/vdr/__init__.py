# -*- encoding: utf-8 -*-
"""
Test utilities for vdr
"""

from keri import core

from keri import app
from keri.app import habbing

def buildHab(db, ks, name="test"):
    """Utility to setup Habery and Hab for testing purposes
    Returns:
       tuple (Habery, Hab):
    """

    raw = b"raw salt to test"

    #  create secrecies
    secrecies = [[signer.qb64] for signer in
                    core.Salter(raw=raw).signers(count=8,
                                                   path="name",
                                                   temp=True)]

    # setup hab
    hby = habbing.Habery(name=name, temp=True, ks=ks, db=db)
    hab = hby.makeHab(name=name, secrecies=secrecies)
    return (hby, hab)

