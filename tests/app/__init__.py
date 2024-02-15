# -*- encoding: utf-8 -*-
"""
Test utilities for app
"""
from contextlib import contextmanager

from keri.app import habbing
from keri.core import coring, eventing, parsing
from keri.db import dbing


@contextmanager
def openMultiSig(prefix="test", salt=b'0123456789abcdef', temp=True, **kwa):
    with (habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=temp) as (hby1, hab1),
          habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=temp) as (hby2, hab2),
          habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=temp) as (hby3, hab3)):
        # Keverys so we can process each other's inception messages.
        kev1 = eventing.Kevery(db=hab1.db, lax=True, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=True, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=True, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None  # may need to fix

        inits = dict(
            toad=0,
            wits=[],
            isith='3',
            nsith='3'
        )

        ghab1 = hby1.makeGroupHab(group=f"{prefix}_group1", mhab=hab1,
                                  smids=smids, rmids=rmids, **inits)
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        ghab3 = hby3.makeGroupHab(group=f"{prefix}_group3", mhab=hab3,
                                  smids=smids, rmids=rmids, **inits)

        dgkey = dbing.dgKey(ghab1.pre.encode("utf-8"), ghab1.pre.encode("utf-8"))  # digest key
        eraw = hab1.db.getEvt(dgkey)
        sigs = bytearray()
        sigs.extend(bytes(hab1.db.getSigs(dgkey)[0]))
        sigs.extend(bytes(hab2.db.getSigs(dgkey)[0]))
        sigs.extend(bytes(hab3.db.getSigs(dgkey)[0]))

        evt = bytearray(eraw)
        evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=3).qb64b)  # attach cnt
        evt.extend(sigs)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3, local=True)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2, local=True)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)

        assert ghab1.pre in kev1.kevers
        assert ghab1.pre in kev2.kevers
        assert ghab1.pre in kev3.kevers

        yield (hby1, ghab1), (hby2, ghab2), (hby3, ghab3)

