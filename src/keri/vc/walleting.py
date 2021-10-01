# -*- encoding: utf-8 -*-
"""
keri.vc.walleting module

"""
from hio.base import doing

from .. import help
from ..app import agenting
from ..core.scheming import CacheResolver

# TODO: create this and populate with needed schema for now
from ..vdr import viring

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
            db: (viring.Registry) the database for the wallet

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
        saiders = self.db.schms.get(keys=schema.encode("utf-8"))

        creds = []
        for saider in saiders:
            creder = self.db.creds.get(keys=saider.qb64b)

            # TODO:  de-dupe the seals here and extract the signatures
            seals = self.db.seals.get(keys=saider.qb64b)
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


class WalletDoer(doing.DoDoer):

    def __init__(self, hab, verifier, **kwa):
        """
        Wallter doer processes the verifier cues and escrows for an Enterprise Wallet

        Parameters:
            hab (Habitat) is the local environment associate with this wallet
            verifier (Verifier) is the verifier that processes and stores credentials

        """

        self.verifier = verifier

        doers = [doing.doify(self.escrowDo)]
        self.witq = agenting.WitnessInquisitor(hab=hab, klas=agenting.TCPWitnesser)


        super(WalletDoer, self).__init__(doers=doers, **kwa)


    def escrowDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list

        Processes the Groupy escrow for group icp, rot and ixn request messages.

        """
        # start enter context
        yield  # enter context
        while True:
            self.verifier.processEscrows()
            yield self.tock

    def verifierDo(self, tymth, tock=0.0, **opts):
        """
        Process cues from Verifier coroutine

            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.verifier.cues:
                cue = self.verifier.cues.popleft()
                cueKin = cue["kin"]

                if cueKin == "saved":
                    creder = cue["creder"]

                    logger.info("Credential: %s, Schema: %s,  Saved", creder.said, creder.schema)
                    logger.info(creder.pretty())

                elif cueKin == "query":
                    qargs = cue["q"]
                    self.witq.query(**qargs)

                elif cueKin == "telquery":
                    qargs = cue["q"]
                    self.witq.telquery(**qargs)
                yield self.tock
            yield self.tock
