# -*- encoding: utf-8 -*-
"""
tests.peer.test_exchanging module

"""

from keri.app import habbing, forwarding, storing, signing
from keri.core import coring
from keri.peer import exchanging


def test_exchanger():
    with habbing.openHab(name="sid", base="test", salt=b'0123456789abcdef') as (hby, hab):
        mbx = storing.Mailboxer(hby=hby)
        forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)
        exc = exchanging.Exchanger(db=hby.db, handlers=[forwarder])

        ser, sigs, _ = hab.getOwnEvent(sn=0)
        sadsig = signing.SadPathSigGroup(pather=coring.Pather(path=[]), sigers=sigs)
        act = bytearray()
        pather = coring.Pather(path=["a"])
        sadsig.transpose(pather)
        act.extend(sadsig.proof)

        # create the forward message with payload embedded at `a` field
        fwd = exchanging.exchange(route='/fwd', modifiers=dict(pre="EBCAFG", topic="/delegation"),
                                  payload=ser.ked)
        exnsigs = hab.sign(ser=fwd.raw,
                               verfers=hab.kever.verfers,
                               indexed=True)

        exc.processEvent(serder=fwd, source=hab.kever.prefixer, sigers=exnsigs, sadsigs=[(sadsig.pather, sadsig.sigers)])

        assert len(forwarder.msgs) == 1
        msg = forwarder.msgs.popleft()

        assert msg["payload"] == ser.ked
        assert msg["modifiers"] == {'pre': 'EBCAFG', 'topic': '/delegation'}
        assert msg["pre"].qb64b == hab.kever.prefixer.qb64b
        assert msg["attachments"] == []
