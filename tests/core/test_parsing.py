# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import os

import pytest
from hio.help import decking


from keri.kering import ValidationError

from keri import help

from keri import core
from keri.core import parsing, coring
from keri.core.coring import (CtrDex, Counter,)
from keri.core.eventing import (Kever, Kevery, incept, rotate, interact)

from keri.db.basing import openDB
from keri.app import habbing
from keri.peer import exchanging

logger = help.ogler.getLogger()


def test_parser():
    """
    Test the support functionality for Parser stream processor
    """
    logger.setLevel("ERROR")

    #  create signers
    raw = b"ABCDEFGH01234567"
    signers = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        event_digs = []  # list of event digs in sequence

        # create event stream
        msgs = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers[1].verfer.qb64b).qb64])
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger], db=conDB)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        assert msgs == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                    b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                    b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                    b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                    b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}-AABAAApXLez5eVIs6YyR'
                    b'XOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-Im'
                    b'DmGPM8E')

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[1].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[1].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 2 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[2].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 3 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=3)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 4 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=4)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 5 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[3].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 6 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=6)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[4].verfer.qb64],
                        dig=kever.serder.said,
                        sn=7)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Interaction but already abandoned
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=8)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nulled so reject any more events
            kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Rotation override interaction but already abandoned
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[4].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8)
        # create sig counter
        counter = Counter(CtrDex.ControllerIdxSigs)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        assert len(msgs) == 3745

        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(db=valDB)

        parser = parsing.Parser(kvy=kevery)
        assert parser.kvy == kevery
        assert parser.local == False
        assert parser.framed == True
        assert parser.pipeline == False
        assert parser.ims == bytearray()

        parser.parse(ims=bytearray(msgs))  # make copy
        assert parser.ims == bytearray(b'')  # emptied
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs

        parser = parsing.Parser()  # no kevery so drops all messages
        parser.parse(ims=msgs)
        assert parser.ims == bytearray(b'')

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """




if __name__ == "__main__":
    test_parser()
