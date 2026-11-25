# -*- encoding: utf-8 -*-
"""
tests.core.test_ld_escrow module

Regression test for the KEL likely-duplicitous escrow.

A duplicitous KEL event (a second, different event at an already-accepted sn
that is not a valid recovery) must route through Kevery.escrowLDEvent, land in
the .ldes escrow, and raise LikelyDuplicitousError. The escrow write and the
escrow reader (Kevery.processEscrowDuplicitous) must agree on the key form, so
the escrowed event round-trips through db.ldes.getAllItemIter.

This exercises the Kevery/KEL path specifically: the pre-existing
LikelyDuplicitousError tests live in tests/vdr/test_eventing.py and drive the
TEL/Tevery path, which raises without ever touching the .ldes escrow — so they
did not cover escrowLDEvent, and a rename of the escrow write API went unnoticed.
"""

from keri.kering import Vrsn_1_0, Kinds, LikelyDuplicitousError
from keri.core import Salter, Diger, Kevery, incept, interact
from keri.db import openDB

import pytest


def test_kel_likely_duplicitous_escrow():
    """A duplicitous KEL event is escrowed in .ldes and raises LikelyDuplicitousError."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = Salter(raw=b"ABCDEFGH01234567").signers(count=8, path='ld', temp=True)

    with openDB(name="dup") as db:
        kevery = Kevery(db=db, lax=False, local=True)

        # icp@0
        icp = incept(keys=[signers[0].verfer.qb64],
                     ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=icp, sigers=[signers[0].sign(icp.raw, index=0)])
        pre = icp.pre
        assert pre in kevery.kevers  # accepted

        # ixn@1 (in order) — accepted, advances sn to 1
        ixn = interact(pre=pre, dig=icp.said, sn=1, **kwa)
        kevery.processEvent(serder=ixn, sigers=[signers[0].sign(ixn.raw, index=0)])
        assert kevery.kevers[pre].sn == 1

        # ixn@1' — a DIFFERENT event at the already-accepted sn=1, same prior,
        # extra anchor so its SAID differs. Not a recovery (ixn cannot supersede),
        # so it is duplicitous.
        dup = interact(pre=pre, dig=icp.said, sn=1,
                       data=[{"d": "EAduplicitousfork0000000000000000000000000000"}], **kwa)
        assert dup.said != ixn.said

        with pytest.raises(LikelyDuplicitousError):
            kevery.processEvent(serder=dup, sigers=[signers[0].sign(dup.raw, index=0)])

        # The duplicitous event must be captured in the .ldes escrow, readable via
        # the same iterator Kevery.processEscrowDuplicitous walks — same key form
        # (keys=pre, on=sn) the reader and the sibling .ooes escrow use.
        escrowed = [((p.decode() if isinstance(p, (bytes, bytearray)) else p),
                     sn,
                     (edig.decode() if isinstance(edig, (bytes, bytearray)) else edig))
                    for (p,), sn, edig in db.ldes.getAllItemIter(keys=b'')]
        assert (pre, 1, dup.said) in escrowed, \
            f"duplicitous event not round-tripped through .ldes; got {escrowed}"

        # Drive the reader (processEscrowDuplicitous) on the now-live path: it must
        # walk the escrow with the same key form (keys=pre, on=sn) without crashing.
        # The event is still duplicitous, so the reader re-raises LikelyDuplicitousError
        # internally and keeps the entry escrowed rather than removing it.
        kevery.processEscrowDuplicitous()
        still = [((p.decode() if isinstance(p, (bytes, bytearray)) else p),
                  sn,
                  (edig.decode() if isinstance(edig, (bytes, bytearray)) else edig))
                 for (p,), sn, edig in db.ldes.getAllItemIter(keys=b'')]
        assert (pre, 1, dup.said) in still, \
            f"reader did not round-trip the escrow key form; got {still}"
