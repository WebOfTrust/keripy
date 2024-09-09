# -*- encoding: utf-8 -*-
"""
keri.app.storing module

"""
from dataclasses import asdict

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
            cue = self.cues.pull()
            match cue['kin']:
                case "keyStateSaved":
                    kcue = cue
                    ksn = kcue['ksn']  # key state notice dict
                    match ksn["i"]:
                        case self.pre:
                            if kever.sn < int(ksn["s"], 16):
                                # Add new doer here instead of cueing to a while loop
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
        self.witq.query(src=self.hab.pre, pre=self.ksn["i"])
        super(LogQuerier, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        kever = self.hab.kevers[self.ksn["i"]]
        if kever.sn >= int(self.ksn['s'], 16):
            self.remove([self.witq])
            return True

        return super(LogQuerier, self).recur(tyme, deeds)


class SeqNoQuerier(doing.DoDoer):

    def __init__(self, hby, hab, pre, sn, fn=None, wits=None, **opts):
        self.hby = hby
        self.hab = hab
        self.pre = pre
        self.sn = sn
        self.fn = fn if fn is not None else 0
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.pre,
                        sn="{:x}".format(self.sn),
                        fn="{:x}".format(self.fn),
                        wits=wits)
        super(SeqNoQuerier, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        if self.pre not in self.hab.kevers:
            return False

        kever = self.hab.kevers[self.pre]
        if kever.sn >= self.sn:
            self.remove([self.witq])
            return True

        return super(SeqNoQuerier, self).recur(tyme, deeds)


class AnchorQuerier(doing.DoDoer):

    def __init__(self, hby, hab, pre, anchor, **opts):
        self.hby = hby
        self.hab = hab
        self.pre = pre
        self.anchor = anchor
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.pre, anchor=anchor)
        super(AnchorQuerier, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        if self.pre not in self.hab.kevers:
            return False

        kever = self.hab.kevers[self.pre]
        if self.hby.db.fetchAllSealingEventByEventSeal(self.pre, seal=self.anchor):
            self.remove([self.witq])
            return True

        return super(AnchorQuerier, self).recur(tyme, deeds)
