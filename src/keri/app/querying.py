# -*- encoding: utf-8 -*-
"""
keri.app.storing module

"""

from hio.base import doing
from hio.help import decking

from keri.app import agenting


class QueryDoer(doing.DoDoer):

    def __init__(self, hby, hab, kvy, pre, **kwa):
        doers = []

        self.hby = hby
        self.hab = hab
        self.kvy = kvy
        self.logs = decking.Deck()

        self.pre = pre
        self.loaded = False

        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        doers.extend([self.witq, doing.doify(self.keyStateCueDo), doing.doify(self.logsDo)])

        self.toRemove = list(doers)
        doers.extend([doing.doify(self.queryDo)])
        super(QueryDoer, self).__init__(doers=doers, **kwa)

    def queryDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        self.witq.query(src=self.hab.pre, pre=self.pre, r="ksn")

        while not self.loaded:
            yield 1.0

        self.remove(self.toRemove)

        return

    def keyStateCueDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            if self.pre in self.hby.kevers:
                kever = self.hab.kevers[self.pre]
            else:
                continue

            kcue = None
            for cue in self.kvy.cues:
                match cue['kin']:
                    case "keyStateSaved":
                        kcue = cue
                        break
           
            if kcue is not None:
                self.kvy.cues.remove(kcue)

                ksn = kcue['serder']
                match ksn.pre:
                    case self.pre:
                        if kever.sn < ksn.sn:
                            print("New key events are available, loading now...")
                            self.logs.append(ksn)
                        else:
                            self.loaded = True

                        continue
                    case _:
                        continue

            yield self.tock

    def logsDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.logs:
                ksn = self.logs.popleft()
                print(f"Querying for new events up to {ksn.sn}")
                kever = self.hab.kevers[ksn.pre]

                self.witq.query(src=self.hab.pre, pre=ksn.pre)

                while kever.sn < ksn.sn:
                    yield self.tock

                print("Key event log synced successfully")
                self.loaded = True
                return

            yield self.tock
