# -*- encoding: utf-8 -*-
"""
keri.kli.common.oobiing module

"""
from hio.base import doing
from hio.help import decking

from keri.app.cli.common import terming
from keri.end import ending


class OobiLoader(doing.DoDoer):
    """ DoDoer for loading oobis and waiting for the results """

    def __init__(self, hby, oobis=None, auto=False):
        """

        Parameters:
            db (Baser) database with preloaded oobis:
            oobis (list): optional list of oobis to load
            auto (bool): True means load oobis from database
        """

        self.processed = 0
        self.db = hby.db
        self.oobis = oobis if oobis is not None else decking.Deck()

        self.oobiery = ending.Oobiery(hby=hby)
        if auto:
            for ((oobi,), _) in self.db.oobis.getItemIter():
                self.oobiery.oobis.append(dict(url=oobi))
                self.oobis.append(oobi)

        doers = [self.oobiery, doing.doify(self.loadDo)]

        super(OobiLoader, self).__init__(doers=doers)

    def queue(self, oobis):
        """ Queue up a list of oobis to process, then exit

        Parameters:
            oobis (list): list of OOBIs to resolve.

        """
        for oobi in oobis:
            self.oobiery.oobis.append(oobi)
            self.oobis.append(oobi["url"])

    def loadDo(self, tymth, tock=0.0):
        """ Load oobis

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method for loading oobis using
        the Oobiery
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.oobis:  # wait until we have some OOBIs to process
            yield self.tock

        while True:
            if not self.oobis:
                yield self.tock
                break

            while self.oobiery.cues:
                cue = self.oobiery.cues.popleft()
                kin = cue["kin"]
                oobi = cue["oobi"]
                if kin in ("resolved",):
                    print(oobi, "succeeded")
                    self.oobis.remove(oobi)
                if kin in ("failed",):
                    print(oobi, "failed")
                    self.oobis.remove(oobi)

                yield 0.25

            yield self.tock

        self.remove([self.oobiery])
