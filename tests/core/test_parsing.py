# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import os

import pytest
from hio.help import decking


from keri.kering import ValidationError, Vrsn_1_0, Vrsn_2_0

from keri import help

from keri import core
from keri.core import coring, Counter, Codens, Seqner, Dater
from keri.core.parsing import Parser

from keri.core.eventing import (Kever, Kevery, incept, rotate, interact)

from keri.db.basing import openDB
from keri.app import habbing
from keri.peer import exchanging

logger = help.ogler.getLogger()


def test_parser():
    """
    Test the support functionality for Parser stream processor

    Use openHby instead more updated approach to generating events

    """
    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        event_digs = []  # list of event digs in sequence

        # create event stream
        msgs = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers[1].verfer.qb64b).qb64])
        event_digs.append(serder.said)
        # extend key event stream with msg
        msgs.extend(serder.raw)
        assert msgs == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs,  # default is count = 1
        counter = Counter(Codens.ControllerIdxSigs, count=2, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        siger0 = signers[0].sign(serder.raw, index=0)  # return siger
        msgs.extend(siger0.qb64b)
        siger1 = signers[1].sign(serder.raw, index=1)  # return siger
        msgs.extend(siger1.qb64b)

        # add witness indexed sigs
        counter = Counter(Codens.WitnessIdxSigs, count=2, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        wiger0 = signers[0].sign(serder.raw, index=0)  # return wiger
        msgs.extend(wiger0.qb64b)
        wiger1 = signers[1].sign(serder.raw, index=1)  # return wiger
        msgs.extend(wiger1.qb64b)

        # add non trans receipt couples
        counter = Counter(Codens.NonTransReceiptCouples, count=2, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        cigar0 = nsigners[0].sign(serder.raw)  # return cigar since no index
        msgs.extend(cigar0.verfer.qb64b)
        msgs.extend(cigar0.qb64b)
        cigar1 = nsigners[1].sign(serder.raw)  # return cigar since no index
        msgs.extend(cigar1.verfer.qb64b)
        msgs.extend(cigar1.qb64b)

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        counter = Counter(Codens.TransReceiptQuadruples, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(serder.pre.encode())
        msgs.extend(Seqner(snh=serder.snh).qb64b)
        msgs.extend(serder.said.encode())
        tiger = signers[0].sign(serder.raw, index=0)  # return siger
        msgs.extend(tiger.qb64b)

        # add Trans Indexed Sig Groups
        counter = Counter(Codens.TransIdxSigGroups, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(serder.pre.encode())
        msgs.extend(Seqner(snh=serder.snh).qb64b)
        msgs.extend(serder.said.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        msgs.extend(siger.qb64b)

        # add Trans Last Indexed Sig Groups
        counter = Counter(Codens.TransLastIdxSigGroups, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(serder.pre.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        msgs.extend(siger.qb64b)

        # add first seen replay couple
        counter = Counter(Codens.FirstSeenReplayCouples, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(Seqner(snh=serder.snh).qb64b)
        msgs.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)

        # add seal source couple
        counter = Counter(Codens.SealSourceCouples, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(Seqner(snh=serder.snh).qb64b)
        msgs.extend(serder.said.encode())

        # add seal source triple
        counter = Counter(Codens.SealSourceTriples, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(serder.pre.encode())
        msgs.extend(Seqner(snh=serder.snh).qb64b)
        msgs.extend(serder.said.encode())


        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger0], db=conDB)


        #assert msgs == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        #b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        #b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        #b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        #b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}-AACAAApXLez5eVIs6YyR'
                        #b'XOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-Im'
                        #b'DmGPM8EABCPC62EHHb9FSyz39Oow0wZi5-riGPzdkzyAMxjdmYYBNyAymnTTK6pH'
                        #b'K2eI2H9LtGRHPI6Yn6UWVcdZt3frToL')

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[1].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
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
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        #assert len(msgs) == 3745
        #assert len(msgs) == 3833

        pre = kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(db=valDB)

        parser = Parser(kvy=kevery)
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

        parser = Parser()  # no kevery so drops all messages
        parser.parse(ims=msgs)
        assert parser.ims == bytearray(b'')

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """




if __name__ == "__main__":
    test_parser()
