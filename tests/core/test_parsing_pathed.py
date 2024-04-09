# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""

from hio.help import decking

from keri import help

from keri import core
from keri.core import parsing, coring
from keri.peer import exchanging
from keri.app import habbing


logger = help.ogler.getLogger()


def test_pathed_material(mockHelpingNowUTC):
    class MockHandler:
        resource = "/fwd"
        local = True

        def __init__(self):
            self.msgs = decking.Deck()
            self.atcs = decking.Deck()

        def handle(self, serder, attachments=None):
            self.msgs.append(serder)
            self.atcs.append(attachments)

    with (habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as hby,
          habbing.openHby(name="deb", base="test", salt=core.Salter(raw=b'0123456789abcdef').qb64) as debHby):
        sith = ["1/2", "1/2", "1/2"]  # weighted signing threshold
        palHab = hby.makeHab(name="pal")
        debHab = debHby.makeHab(name="deb", isith=sith, icount=3)
        # Create series of events
        debMsgs = dict(icp=debHab.makeOwnInception(), ixn0=debHab.interact(), rot=debHab.rotate(),
                       ixn1=debHab.interact())
        fwd, end = exchanging.exchange(route='/fwd',
                                       modifiers=dict(pre=palHab.pre, topic="replay"), payload={}, embeds=debMsgs,
                                       sender=debHab.pre)
        fwd = debHab.endorse(fwd, last=False, pipelined=False)
        fwd.extend(end)
        handler = MockHandler()
        exc = exchanging.Exchanger(hby=debHby, handlers=[handler])
        parser = parsing.Parser(exc=exc)

        parser.parseOne(ims=fwd)
        assert len(handler.msgs) == 1
        serder = handler.msgs.popleft()

        embeds = serder.ked['e']
        assert len(embeds) == 5
        assert embeds["icp"]["t"] == coring.Ilks.icp
        assert embeds["ixn0"]["t"] == coring.Ilks.ixn
        assert embeds["rot"]["t"] == coring.Ilks.rot
        assert embeds["ixn1"]["t"] == coring.Ilks.ixn
        assert len(handler.atcs) == 1
        attachments = handler.atcs.popleft()
        assert len(attachments) == 4
        (path1, attachment1) = attachments[0]
        assert path1.bext == "-icp"
        assert attachment1 == (b'-AADAADqkN1IwOepXk5LYPaLBCoHWnZpdWZ2qmhLQKY9I-ape8cTqwHKPg5EP98y'
                               b'bxgYDhAzpOkv9BzE2dhVeac0l7cKABBJhNtfZG642LFbrRurILy0iKMoT8bc1Olk'
                               b'cFYDpmCUwIYlH_jNk-7WlxtgunEMMcBvvGl_E5xuZ_Il6YLSUY4JACAIrMoryRki'
                               b'spZKXWabmx2aBrTgTaGBvysk7B3-mcF0Mg1riSikRar5d70gBZIQjAUuE6KYWLd1'
                               b'Sa0CTMzaTZAO')
        (path2, attachment2) = attachments[1]
        assert path2.bext == "-ixn0"
        assert attachment2 == (b'-AADAAA9aT5vgzKjSVl_xcCXiLIUIqYl9___1Gll8Sj6dDIAygsBQ-lVATd1ifTe'
                               b'_DcsKTwY6sCr1a29f1LNOY_tngoLABCUcENmDJH_Xeh7Pc5q8Nwww5FcTJtpHkBT'
                               b'wdeJ-v6aSPUMaTdkXI7n_3r-8ogrDlKddjgYiOTt2V7f53g-JbYCACAVG_IWtYZp'
                               b'Vns4bYI_Acce2HMFjrM26cB_OuyHdYHx7S5SDrJmnKeQvSnMGGq_MiBGf3RhW7sz'
                               b'Qw1zFwSHKEMI')


if __name__ == "__main__":
    pass
