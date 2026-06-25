# -*- encoding: utf-8 -*-
"""
Test utilities for app
"""
from contextlib import contextmanager

from keri.app import grouping, habbing
from keri import kering, core
from keri.core import coring, eventing, parsing, serdering
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
        evt.extend(core.Counter(code=core.Codens.ControllerIdxSigs,
                                count=3, gvrsn=kering.Vrsn_1_0).qb64b)  # attach cnt
        evt.extend(sigs)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3, local=True)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2, local=True)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)

        assert ghab1.pre in kev1.kevers
        assert ghab1.pre in kev2.kevers
        assert ghab1.pre in kev3.kevers

        yield (hby1, ghab1), (hby2, ghab2), (hby3, ghab3)


def _completeGroupEvent(hby, ghab, seqner, saider):
    """Drive the local counselor/escrows until a group event is committed."""
    counselor = grouping.Counselor(hby=hby)
    prefixer = coring.Prefixer(qb64=ghab.pre)
    counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=saider)

    # These tests have no witnesses/mailboxes; local escrow pumping is enough.
    for _ in range(8):
        hby.kvy.processEscrows()
        counselor.processEscrows()
        if counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider):
            return

    raise AssertionError(f"group event {ghab.pre}:{seqner.sn} did not complete")


@contextmanager
def openLateJoinerMultisig(helpers, prefix="late-joiner", base=None, group="multisig", salt=None):
    """Create a two-store late-joiner multisig fixture.

    Setup:
        Multisig starts with m1 in a one-member group that has already committed to
        member 2 as a future member.

    Body:
        The body of the context manager may create registry and credential state
        before calling addLateJoiner(), leaving the late store without that VC state
        until export/import runs.

    Usage:
        yields single member multisig, haberies for both initial (source) and late joiner,
        and the function to rotate in the late joiner.
    """
    if base is None:
        raise ValueError("openLateJoinerMultisig requires a per-test base")

    if salt is None:
        salt = core.Salter(raw=b'0123456789abcdef').qb64

    with (habbing.openHby(name=f"{prefix}-source", base=base, temp=False, clear=True, salt=salt) as srcHby,
          habbing.openHby(name=f"{prefix}-late", base=base, temp=False, clear=True, salt=salt) as lateHby):
        try:
            m1Hab = srcHby.makeHab(name="m1", icount=1, isith="1", ncount=1, nsith="1")
            m2Hab = lateHby.makeHab(name="m2", icount=1, isith="1", ncount=1, nsith="1")

            # The first member knows the future rotating member; the late member remains otherwise empty.
            parsing.Parser().parse(ims=bytearray(m2Hab.makeOwnEvent(sn=0)), kvy=srcHby.kvy)
            groupHab = srcHby.makeGroupHab(group=group,
                                           mhab=m1Hab,
                                           smids=[m1Hab.pre],
                                           rmids=[m1Hab.pre, m2Hab.pre],
                                           isith="1",
                                           nsith="2",
                                           toad=0,
                                           wits=[])
            _completeGroupEvent(srcHby,
                                groupHab,
                                seqner=coring.Seqner(sn=0),
                                saider=coring.Saider(qb64=groupHab.pre))

            def addLateJoiner():
                """
                Promote member 2 to a 2-of-2 group without importing VC state.

                Run this after performing registry and credential setup in the body of the
                context manager call site.
                """
                m1Hab.rotate()
                m2Hab.rotate()
                parsing.Parser().parse(ims=bytearray(m2Hab.makeOwnEvent(sn=1)), kvy=srcHby.kvy)

                smids = [m1Hab.pre, m2Hab.pre]
                rmids = [m1Hab.pre, m2Hab.pre]
                merfers = [m1Hab.kever.verfers[0], m2Hab.kever.verfers[0]]
                migers = [m1Hab.kever.ndigers[0], m2Hab.kever.ndigers[0]]
                seqner = coring.Seqner(sn=groupHab.kever.sn + 1)
                rot = groupHab.rotate(smids=smids,
                                      rmids=rmids,
                                      isith="2",
                                      nsith="2",
                                      toad=0,
                                      cuts=[],
                                      adds=[],
                                      verfers=merfers,
                                      digers=migers)
                rserder = serdering.SerderKERI(raw=rot)
                sigers = m2Hab.mgr.sign(rserder.raw,
                                        verfers=m2Hab.kever.verfers,
                                        indexed=True,
                                        indices=[1])
                # Member 2 signs the promotion without importing prior registry or credential state.
                msg = eventing.messagize(serder=rserder, sigers=sigers)
                parsing.Parser().parse(ims=bytearray(msg), kvy=srcHby.kvy)
                _completeGroupEvent(srcHby, groupHab, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

                for msgs in (m1Hab.replay(), m2Hab.replay(), groupHab.replay()):
                    parsing.Parser().parse(ims=bytearray(msgs), kvy=lateHby.kvy)

                # Join only the group KEL locally; registry and credential state must still come from import.
                return lateHby.joinGroupHab(groupHab.pre, group=group, mhab=m2Hab, smids=smids, rmids=rmids)

            yield (srcHby, m1Hab, groupHab), (lateHby, m2Hab), addLateJoiner
        finally:
            helpers.closeHby(lateHby)
            helpers.closeHby(srcHby)
