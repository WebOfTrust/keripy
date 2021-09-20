# -*- encoding: utf-8 -*-
"""
keri.vc.walleting module

"""
from .. import help, kering
from ..core import coring
from ..core.scheming import CacheResolver
from ..db import dbing, subing
from ..kering import UnverifiedProofError

# TODO: create this and populate with needed schema for now
from ..vdr import verifying, viring

cache = CacheResolver()

logger = help.ogler.getLogger()


class Wallet:
    """
    Wallet represents all credentials received or verified


    """

    def __init__(self, db: viring.Registry = None, name="test", temp=False):
        """
        Create a Wallet associated with a Habitat

        Parameters:
            hab (Habitat) is the local environment associate with this wallet

        """
        self.name = name
        self.temp = temp

        self.db = db if db is not None else viring.Registry(name=self.name, temp=self.temp)

    def getCredentials(self, schema=None):
        """
        Return list of (creder, prefixer, seqner, diger, sigers) for each credential
        that matches schema

        Parameters:
            schema: qb64 SAID of the schema for the credential

        """
        saids = self.db.schms.get(keys=schema.encode("utf-8"))

        creds = []
        for said in saids:
            key = bytearray(said)
            creder = self.db.creds.get(keys=key)

            # TODO:  de-dupe the seals here and extract the signatures
            seals = self.db.seals.get(keys=key)
            prefixer = None
            seqner = None
            diger = None
            sigers = []
            for seal in seals:
                (prefixer, seqner, diger, siger) = seal
                sigers.append(siger)

            print("found match")
            print(creder.pretty())

            creds.append((creder, prefixer, seqner, diger, sigers))

        return creds
