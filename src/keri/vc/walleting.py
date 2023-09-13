# -*- encoding: utf-8 -*-
"""
keri.vc.walleting module

"""
from hio.base import doing

from .. import help
from ..app import agenting
from ..vdr import viring

logger = help.ogler.getLogger()


class Wallet:
    """
    Wallet represents all credentials received or verified


    """

    def __init__(self, reger: viring.Reger = None, name="test", temp=False):
        """
        Create a Wallet associated with a Habitat

        Parameters:
            reger: (viring.Registry) the database for the wallet

        """
        self.name = name
        self.temp = temp

        self.reger = reger if reger is not None else viring.Reger(name=self.name, temp=self.temp)

    def getCredentials(self, schema=None):
        """
        Return list of (creder, prefixer, seqner, diger, sigers) for each credential
        that matches schema

        Parameters:
            schema: qb64 SAID of the schema for the credential

        """
        saiders = self.reger.schms.get(keys=schema.encode("utf-8"))

        creds = []
        for saider in saiders:
            creder, prefixer, seqner, saider = self.reger.cloneCred(said=saider.qb64)
            creds.append((creder, prefixer, seqner, saider))

        return creds


class WalletDoer(doing.DoDoer):
    """ DoDoer for process escrows and cues associated with a wallet

    """

    def __init__(self, hby, verifier, **kwa):
        """ Waller doer processes the verifier cues and escrows for an Enterprise Wallet

        Parameters:
            hab (Habitat): is the local environment associate with this wallet
            verifier (Verifier): is the verifier that processes and stores credentials

        """

        self.verifier = verifier

        doers = [doing.doify(self.escrowDo)]
        self.witq = agenting.WitnessInquisitor(hby=hby, klas=agenting.TCPMessenger)

        super(WalletDoer, self).__init__(doers=doers, **kwa)

    def escrowDo(self, tymth, tock=0.0):
        """ Processes the escrows for group icp, rot and ixn request messages.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list

        Returns:
             Doist: doifiable Doist compatible generator method

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            self.verifier.processEscrows()
            yield self.tock

    def verifierDo(self, tymth, tock=0.0):
        """ Process cues from Verifier coroutine

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

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
