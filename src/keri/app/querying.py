# -*- encoding: utf-8 -*-
"""
keri.app.storing module

"""

from hio.base import doing
from keri.app import agenting


class QueryDoer(doing.DoDoer):

    def __init__(self, hby, hab, kvy, pre, **kwa):
        self.hby = hby
        self.hab = hab
        self.kvy = kvy
        self.pre = pre

        doers = [KeyStateNoticer(hby=hby, hab=self.hab, pre=pre, cues=kvy.cues)]
        super(QueryDoer, self).__init__(doers=doers, **kwa)


class KeyStateNoticer(doing.DoDoer):

    def __init__(self, hby, hab, pre, cues, **opts):
        self.hby = hby
        self.hab = hab
        self.pre = pre
        self.cues = cues
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.pre, r="ksn")

        super(KeyStateNoticer, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        if self.pre in self.hby.kevers:
            kever = self.hby.kevers[self.pre]
        else:
            return super(KeyStateNoticer, self).recur(tyme, deeds)

        if self.cues:
            cue = self.cues.popleft()
            match cue['kin']:
                case "keyStateSaved":
                    kcue = cue
                    ksn = kcue['serder']
                    match ksn.pre:
                        case self.pre:
                            if kever.sn < ksn.sn:
                                # Add new doer here instead of cueing to a while loop
                                print("New key events are available, loading now...")
                                self.extend([LogQuerier(hby=self.hby, hab=self.hab, ksn=ksn)])
                                self.remove([self.witq])

                            else:
                                return True

                        case _:
                            self.cues.append(cue)

                case _:
                    self.cues.append(cue)

        return super(KeyStateNoticer, self).recur(tyme, deeds)


class LogQuerier(doing.DoDoer):

    def __init__(self, hby, hab, ksn, **opts):
        self.hby = hby
        self.hab = hab
        self.ksn = ksn
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.ksn.pre)
        super(LogQuerier, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        kever = self.hab.kevers[self.ksn.pre]
        if kever.sn >= self.ksn.sn:
            self.remove([self.witq])
            print("Key event log synced successfully")
            return True

        return super(LogQuerier, self).recur(tyme, deeds)
