# -*- encoding: utf-8 -*-
"""
tests.core.test_eventing module

"""
import os

import pytest
from hio.help import decking


from keri.kering import ValidationError, Vrsn_1_0, Vrsn_2_0, Kinds

from keri import help

from keri import core
from keri.core import coring
from keri.core import (Counter, GenDex, Codens, Seqner, Dater, Texter, Pather,
                       Blinder, Mediar, TypeMedia, Sealer, SealKind, Verser)
from keri.core.parsing import Parser

from keri.core.eventing import (Kever, Kevery, incept, rotate, interact)

from keri.db.basing import openDB
from keri.app import habbing
from keri.peer import exchanging

logger = help.ogler.getLogger()


def test_parser_v1_basic():
    """Test the support functionality for Parser stream processor CESR v1 basic
    non-version non-enclosed attachments

    """
    parser = Parser()  # test defaults
    assert parser.genus == GenDex.KERI
    assert parser.version == Vrsn_2_0
    assert parser.methods == Parser.Methods[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.codes == Parser.Codes[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.sucodes == Parser.SUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.mucodes == Parser.MUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]

    assert not parser.local
    assert parser.ims == bytearray()
    assert parser.framed
    assert not parser.piped
    assert parser.kvy is None
    assert parser.tvy is None
    assert parser.exc is None
    assert parser.rvy is None
    assert parser.vry is None


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

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.PathedMaterialCouples, count=count, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(pms)

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.BigPathedMaterialCouples, count=count, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(pms)

        # add ESSRPayloadGroup
        counter = Counter(Codens.ESSRPayloadGroup, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        texter = Texter(text=b"MeBeEssr")
        msgs.extend(texter.qb64b)

        # add BigESSRPayloadGroup
        counter = Counter(Codens.BigESSRPayloadGroup, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        texter = Texter(text=b"MeBeBigEssr")
        msgs.extend(texter.qb64b)


        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger0], db=conDB)


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

        parser = Parser(kvy=kevery, version=Vrsn_1_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs

        parser = Parser()  # default is V2 parser but stream is V1
        parser.parse(ims=bytearray(msgs))  # catches error can't parse V1 stream
        assert parser.ims == bytearray(b'')  # flushes stream


    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """

def test_parser_v1_version():
    """Test the support functionality for Parser stream processor CESR v1
    genus-version code

    """
    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers1 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners1 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        event_digs = []  # list of event digs in sequence

        # create event stream
        msgs = bytearray()

        # both V1 and V2 counters when doing genus-version return same value
        # for same genus-version
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                                version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                      minor=Vrsn_1_0.minor),
                            code=Codens.KERIACDCGenusVersion,
                            version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_1_0

        assert gvc2.qb64 == gvc1.qb64

        msgs.extend(gvc1.qb64b)  # insert genus-version code at top-level


        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers1[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers1[1].verfer.qb64b).qb64])
        pre = serder.pre
        event_digs.append(serder.said)
        # extend key event stream with msg
        msgs.extend(serder.raw)
        assert serder.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs,  # default is count = 1
        counter = Counter(Codens.ControllerIdxSigs, count=2, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        siger0 = signers1[0].sign(serder.raw, index=0)  # return siger
        msgs.extend(siger0.qb64b)
        siger1 = signers1[1].sign(serder.raw, index=1)  # return siger
        msgs.extend(siger1.qb64b)

        # add witness indexed sigs
        counter = Counter(Codens.WitnessIdxSigs, count=2, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        wiger0 = signers1[0].sign(serder.raw, index=0)  # return wiger
        msgs.extend(wiger0.qb64b)
        wiger1 = signers1[1].sign(serder.raw, index=1)  # return wiger
        msgs.extend(wiger1.qb64b)

        # add non trans receipt couples
        counter = Counter(Codens.NonTransReceiptCouples, count=2, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        cigar0 = nsigners1[0].sign(serder.raw)  # return cigar since no index
        msgs.extend(cigar0.verfer.qb64b)
        msgs.extend(cigar0.qb64b)
        cigar1 = nsigners1[1].sign(serder.raw)  # return cigar since no index
        msgs.extend(cigar1.verfer.qb64b)
        msgs.extend(cigar1.qb64b)

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        counter = Counter(Codens.TransReceiptQuadruples, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(serder.pre.encode())
        msgs.extend(Seqner(snh=serder.snh).qb64b)
        msgs.extend(serder.said.encode())
        tiger = signers1[0].sign(serder.raw, index=0)  # return siger
        msgs.extend(tiger.qb64b)

        # add Trans Indexed Sig Groups
        counter = Counter(Codens.TransIdxSigGroups, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(serder.pre.encode())
        msgs.extend(Seqner(snh=serder.snh).qb64b)
        msgs.extend(serder.said.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        siger = signers1[0].sign(serder.raw, index=0)  # return siger
        msgs.extend(siger.qb64b)

        # add Trans Last Indexed Sig Groups
        counter = Counter(Codens.TransLastIdxSigGroups, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(serder.pre.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        siger = signers1[0].sign(serder.raw, index=0)  # return siger
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

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.PathedMaterialCouples, count=count, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(pms)

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.BigPathedMaterialCouples, count=count, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(pms)

        # add ESSRPayloadGroup
        counter = Counter(Codens.ESSRPayloadGroup, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        texter = Texter(text=b"MeBeEssr")
        msgs.extend(texter.qb64b)

        # add BigESSRPayloadGroup
        counter = Counter(Codens.BigESSRPayloadGroup, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        texter = Texter(text=b"MeBeBigEssr")
        msgs.extend(texter.qb64b)

        assert msgs.startswith(gvc2.qb64b)

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 0

    assert not os.path.exists(kevery.db.path)

    """ Done Test """


def test_parser_v1_enclosed_attachments():
    """Test the support functionality for Parser stream processor with CESRv1
    with versioned and enclosed attachments

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
        # create event stream
        msgs = bytearray()


        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers[1].verfer.qb64b).qb64])
        pre = serder.pre
        # extend key event stream with msg
        msgs.extend(serder.raw)
        assert msgs == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # eventually enclose all attachments in AttachmentGroup
        emas = bytearray()  # enclosed message attachment stream
        # put first code in attachments as genus-version counters
        gvcounter1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                           minor=Vrsn_1_0.minor),
                                 code=Codens.KERIACDCGenusVersion,
                                     version=Vrsn_1_0)
        assert gvcounter1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvcounter1.countToB64(l=3)) == Vrsn_1_0

        emas.extend(gvcounter1.qb64b)  # insert genus-version code at top-level

        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs,  # default is count = 1
        counter = Counter(Codens.ControllerIdxSigs, count=2, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        siger0 = signers[0].sign(serder.raw, index=0)  # return siger
        emas.extend(siger0.qb64b)
        siger1 = signers[1].sign(serder.raw, index=1)  # return siger
        emas.extend(siger1.qb64b)

        # add witness indexed sigs
        counter = Counter(Codens.WitnessIdxSigs, count=2, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        wiger0 = signers[0].sign(serder.raw, index=0)  # return wiger
        emas.extend(wiger0.qb64b)
        wiger1 = signers[1].sign(serder.raw, index=1)  # return wiger
        emas.extend(wiger1.qb64b)

        # add non trans receipt couples
        counter = Counter(Codens.NonTransReceiptCouples, count=2, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        cigar0 = nsigners[0].sign(serder.raw)  # return cigar since no index
        emas.extend(cigar0.verfer.qb64b)
        emas.extend(cigar0.qb64b)
        cigar1 = nsigners[1].sign(serder.raw)  # return cigar since no index
        emas.extend(cigar1.verfer.qb64b)
        emas.extend(cigar1.qb64b)

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        counter = Counter(Codens.TransReceiptQuadruples, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(serder.pre.encode())
        emas.extend(Seqner(snh=serder.snh).qb64b)
        emas.extend(serder.said.encode())
        tiger = signers[0].sign(serder.raw, index=0)  # return siger
        emas.extend(tiger.qb64b)

        # add Trans Indexed Sig Groups
        counter = Counter(Codens.TransIdxSigGroups, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(serder.pre.encode())
        emas.extend(Seqner(snh=serder.snh).qb64b)
        emas.extend(serder.said.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        emas.extend(siger.qb64b)

        # add Trans Last Indexed Sig Groups
        counter = Counter(Codens.TransLastIdxSigGroups, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(serder.pre.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        emas.extend(siger.qb64b)

        # add first seen replay couple
        counter = Counter(Codens.FirstSeenReplayCouples, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(Seqner(snh=serder.snh).qb64b)
        emas.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)

        # add seal source couple
        counter = Counter(Codens.SealSourceCouples, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(Seqner(snh=serder.snh).qb64b)
        emas.extend(serder.said.encode())

        # add seal source triple
        counter = Counter(Codens.SealSourceTriples, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(serder.pre.encode())
        emas.extend(Seqner(snh=serder.snh).qb64b)
        emas.extend(serder.said.encode())

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.PathedMaterialCouples, count=count, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(pms)

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.BigPathedMaterialCouples, count=count, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        emas.extend(pms)

        # add ESSRPayloadGroup
        counter = Counter(Codens.ESSRPayloadGroup, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        texter = Texter(text=b"MeBeEssr")
        emas.extend(texter.qb64b)

        # add BigESSRPayloadGroup
        counter = Counter(Codens.BigESSRPayloadGroup, count=1, version=Vrsn_1_0)
        emas.extend(counter.qb64b)
        texter = Texter(text=b"MeBeBigEssr")
        emas.extend(texter.qb64b)

        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup, version=Vrsn_1_0))

        # Event 1 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[1].sign(serder.raw, index=0)  # returns siger

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 2 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 3 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 4 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 5 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 6 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=pre,
                        keys=[signers[4].verfer.qb64],
                        dig=serder.said,
                        sn=7)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Interaction but already abandoned
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Rotation override interaction but already abandoned
        serder = rotate(pre=pre,
                        keys=[signers[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """


def test_parser_v1_enclosed_message():
    """Test the support functionality for Parser stream processor with CESRv1
    with versioned and enclosed message+attachments group

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
        # create event stream
        msgs = bytearray()

        # eventually enclose message plus attachments in BodyWithAttachmentGroup
        # put genus-version at front of BodyWithAttachmentGroup substream
        eims = bytearray()  # enclosed message+attachment stream

        # put as genus-version counter first in BodyWithAttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                 minor=Vrsn_1_0.minor),
                       code=Codens.KERIACDCGenusVersion,
                       version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0
        eims.extend(gvc1.qb64b)  # add genus-version code at top-level


        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers[1].verfer.qb64b).qb64])
        pre = serder.pre
        assert serder.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        eims.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_1_0))

        # do not enclose attachments in own attachment group
        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs,  # default is count = 1
        counter = Counter(Codens.ControllerIdxSigs, count=2, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        siger0 = signers[0].sign(serder.raw, index=0)  # return siger
        eims.extend(siger0.qb64b)
        siger1 = signers[1].sign(serder.raw, index=1)  # return siger
        eims.extend(siger1.qb64b)

        # add witness indexed sigs
        counter = Counter(Codens.WitnessIdxSigs, count=2, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        wiger0 = signers[0].sign(serder.raw, index=0)  # return wiger
        eims.extend(wiger0.qb64b)
        wiger1 = signers[1].sign(serder.raw, index=1)  # return wiger
        eims.extend(wiger1.qb64b)

        # add non trans receipt couples
        counter = Counter(Codens.NonTransReceiptCouples, count=2, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        cigar0 = nsigners[0].sign(serder.raw)  # return cigar since no index
        eims.extend(cigar0.verfer.qb64b)
        eims.extend(cigar0.qb64b)
        cigar1 = nsigners[1].sign(serder.raw)  # return cigar since no index
        eims.extend(cigar1.verfer.qb64b)
        eims.extend(cigar1.qb64b)

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        counter = Counter(Codens.TransReceiptQuadruples, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(serder.pre.encode())
        eims.extend(Seqner(snh=serder.snh).qb64b)
        eims.extend(serder.said.encode())
        tiger = signers[0].sign(serder.raw, index=0)  # return siger
        eims.extend(tiger.qb64b)

        # add Trans Indexed Sig Groups
        counter = Counter(Codens.TransIdxSigGroups, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(serder.pre.encode())
        eims.extend(Seqner(snh=serder.snh).qb64b)
        eims.extend(serder.said.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        eims.extend(siger.qb64b)

        # add Trans Last Indexed Sig Groups
        counter = Counter(Codens.TransLastIdxSigGroups, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(serder.pre.encode())
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        siger = signers[0].sign(serder.raw, index=0)  # return siger
        eims.extend(siger.qb64b)

        # add first seen replay couple
        counter = Counter(Codens.FirstSeenReplayCouples, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(Seqner(snh=serder.snh).qb64b)
        eims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)

        # add seal source couple
        counter = Counter(Codens.SealSourceCouples, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(Seqner(snh=serder.snh).qb64b)
        eims.extend(serder.said.encode())

        # add seal source triple
        counter = Counter(Codens.SealSourceTriples, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(serder.pre.encode())
        eims.extend(Seqner(snh=serder.snh).qb64b)
        eims.extend(serder.said.encode())

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.PathedMaterialCouples, count=count, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(pms)

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.BigPathedMaterialCouples, count=count, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        eims.extend(pms)

        # add ESSRPayloadGroup
        counter = Counter(Codens.ESSRPayloadGroup, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        texter = Texter(text=b"MeBeEssr")
        eims.extend(texter.qb64b)

        # add BigESSRPayloadGroup
        counter = Counter(Codens.BigESSRPayloadGroup, count=1, version=Vrsn_1_0)
        eims.extend(counter.qb64b)
        texter = Texter(text=b"MeBeBigEssr")
        eims.extend(texter.qb64b)

        # enclose  message+attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=eims, code=Codens.BodyWithAttachmentGroup, version=Vrsn_1_0))

        # next event
        # eventually enclose message plus attachment in AttachmentGroup in BodyWithAttachmentGroup
        eims = bytearray()  # enclosed message+attachment stream
        # Event 1 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1)

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        eims.extend(Counter.enclose(qb64=texter.qb64b,
                                        code=Codens.NonNativeBodyGroup,
                                        version=Vrsn_1_0))

        aims = bytearray()  # attachment group stream
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        # sign serialization
        siger = signers[1].sign(serder.raw, index=0)  # returns siger
        aims.extend(siger.qb64b)

        # enclose attachements and add to eims
        eims.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup, version=Vrsn_1_0))

        # enclose  message+attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=eims, code=Codens.BodyWithAttachmentGroup, version=Vrsn_1_0))


        # Next event
        # eventually enclose message plus attachment in AttachmentGroup in BodyWithAttachmentGroup
        eims = bytearray()  # enclosed message+attachment stream
        # Event 2 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2)

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        eims.extend(Counter.enclose(qb64=texter.qb64b,
                                        code=Codens.NonNativeBodyGroup,
                                            version=Vrsn_1_0))

        aims = bytearray()  # attachment group stream
        # genus-version counter as first in AttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                           version=Vrsn_1_0)
        aims.extend(gvc1.qb64b)  # add genus-version code to attachment group

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)  # returns siger
        aims.extend(siger.qb64b)

        # enclose attachements and add to eims
        eims.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup, version=Vrsn_1_0))

        # enclose  message+attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=eims, code=Codens.BodyWithAttachmentGroup, version=Vrsn_1_0))

        # next event
        # eventually enclose message plus attachments in BodyWithAttachmentGroup
        # put genus-version at front of BodyWithAttachmentGroup substream
        eims = bytearray()  # enclosed message+attachment stream

        # put as genus-version counter first in BodyWithAttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                           version=Vrsn_1_0)
        eims.extend(gvc1.qb64b)  # add genus-version code at top-level

        # Event 3 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3)

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        eims.extend(Counter.enclose(qb64=texter.qb64b,
                                        code=Codens.NonNativeBodyGroup,
                                            version=Vrsn_1_0))

        aims = bytearray()  # attachment group stream
        # genus-version counter as first in AttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_1_0)
        aims.extend(gvc1.qb64b)  # add genus-version code to attachment group


        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)
        aims.extend(siger.qb64b)

        # enclose attachements and add to eims
        eims.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup, version=Vrsn_1_0))

        # enclose  message+attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=eims, code=Codens.BodyWithAttachmentGroup, version=Vrsn_1_0))


        # Event 4 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 5 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 6 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=pre,
                        keys=[signers[4].verfer.qb64],
                        dig=serder.said,
                        sn=7)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Interaction but already abandoned
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Rotation override interaction but already abandoned
        serder = rotate(pre=pre,
                        keys=[signers[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """

def test_parser_v1_non_native_message():
    """Test the support functionality for Parser stream processor with CESRv1
    with versioned non-native message group at top level

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
        # create event stream
        msgs = bytearray()


        # put first code in attachments as genus-version counters
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                 minor=Vrsn_1_0.minor),
                       code=Codens.KERIACDCGenusVersion,
                       version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0
        msgs.extend(gvc1.qb64b)  # add genus-version code at top-level


        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers[1].verfer.qb64b).qb64])
        pre = serder.pre
        assert serder.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        msgs.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_1_0))

        # do not enclose attachments in own attachment group
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

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.PathedMaterialCouples, count=count, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(pms)

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        count = len(pms) // 4  # quadlets
        counter = Counter(Codens.BigPathedMaterialCouples, count=count, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        msgs.extend(pms)

        # add ESSRPayloadGroup
        counter = Counter(Codens.ESSRPayloadGroup, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        texter = Texter(text=b"MeBeEssr")
        msgs.extend(texter.qb64b)

        # add BigESSRPayloadGroup
        counter = Counter(Codens.BigESSRPayloadGroup, count=1, version=Vrsn_1_0)
        msgs.extend(counter.qb64b)
        texter = Texter(text=b"MeBeBigEssr")
        msgs.extend(texter.qb64b)


        # Event 1 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1)

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        msgs.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_1_0))

        # create attachment group
        aims = bytearray()
        # genus-version counter as first in AttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_1_0)
        aims.extend(gvc1.qb64b)  # add genus-version code to attachment group
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        # sign serialization
        siger = signers[1].sign(serder.raw, index=0)  # returns siger
        aims.extend(siger.qb64b)
        # enclose attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup, version=Vrsn_1_0))


        # Event 2 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 3 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 4 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[2].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 5 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 6 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[3].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=pre,
                        keys=[signers[4].verfer.qb64],
                        dig=serder.said,
                        sn=7)

        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Interaction but already abandoned
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Rotation override interaction but already abandoned
        serder = rotate(pre=pre,
                        keys=[signers[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers[4].sign(serder.raw, index=0)

        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """


def test_parser_v2_basic():
    """Test the support functionality for Parser stream processor CESR v2 basic
    non-version non-enclosed attachments

    """
    parser = Parser()  # test defaults
    assert parser.genus == GenDex.KERI
    assert parser.version == Vrsn_2_0
    assert parser.methods == Parser.Methods[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.codes == Parser.Codes[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.sucodes == Parser.SUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.mucodes == Parser.MUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]

    assert not parser.local
    assert parser.ims == bytearray()
    assert parser.framed
    assert not parser.piped
    assert parser.kvy is None
    assert parser.tvy is None
    assert parser.exc is None
    assert parser.rvy is None
    assert parser.vry is None


    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        event_digs = []  # list of event digs in sequence


        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_2_0.major,
                                                     minor=Vrsn_2_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                                version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAACAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_2_0


        # create event stream
        msgs = bytearray()

        # Start stream
        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers2[1].verfer.qb64b).qb64],
                        version=Vrsn_2_0)

        pre = serder.pre

        assert serder.raw == (b'{"v":"KERICAACAAJSONAAEt.","t":"icp","d":"EAAaPtGJw566KVqqKQvVu2GKViXDzQCJWe'
                            b'QWhy4tdujg","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":'
                            b'"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1","n":["EFXI'
                            b'x7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        assert serder.sad == \
        {
            'v': 'KERICAACAAJSONAAEt.',
            't': 'icp',
            'd': 'EAAaPtGJw566KVqqKQvVu2GKViXDzQCJWeQWhy4tdujg',
            'i': 'DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx',
            's': '0',
            'kt': '1',
            'k': ['DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx'],
            'nt': '1',
            'n': ['EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2'],
            'bt': '0',
            'b': [],
            'c': [],
            'a': []
        }


        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0


        event_digs.append(serder.said)
        # extend key event stream with msg
        msgs.extend(serder.raw)


        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs group count quadlets
        aims = bytearray()  # attachment substream
        siger0 = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(siger0.qb64b)
        siger1 = signers2[1].sign(serder.raw, index=1)  # return siger
        aims.extend(siger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # add witness indexed sigs
        aims = bytearray()  # attachment substream
        wiger0 = signers2[0].sign(serder.raw, index=0)  # return wiger
        aims.extend(wiger0.qb64b)
        wiger1 = signers2[1].sign(serder.raw, index=1)  # return wiger
        aims.extend(wiger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.WitnessIdxSigs))

        # add non trans receipt couples
        aims = bytearray()  # attachment substream
        cigar0 = nsigners2[0].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar0.verfer.qb64b)
        aims.extend(cigar0.qb64b)
        cigar1 = nsigners2[1].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar1.verfer.qb64b)
        aims.extend(cigar1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.NonTransReceiptCouples))

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(tiger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptQuadruples))

        # add Trans Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransIdxSigGroups))

        # add Trans Last Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransLastIdxSigGroups))

        # add first seen replay couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.FirstSeenReplayCouples))

        # add seal source couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceCouples))

        # add seal source triple
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceTriples))

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=pms, code=Codens.PathedMaterialCouples))

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=pms, code=Codens.BigPathedMaterialCouples))

        # add ESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ESSRPayloadGroup))

        # add BigESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeBigEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.BigESSRPayloadGroup))

        # add BlindedStateQuadruples
        salt = '0ABhY2Rjc3BlY3dvcmtyYXdm'
        sn = 1
        acdc = ''
        state = ''
        blinder0 = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)
        sn = 2
        acdc = 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'  # bob project report ACDC
        state = 'issued'
        blinder1 = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)
        # enclose and extend with quadlet counter,
        aims = Blinder.enclose([blinder0, blinder1]) #enclose defaults to V2
        msgs.extend(aims)

        # add BoundStateSextuples
        salt = '0ABhY2Rjc3BlY3dvcmtyYXdm'
        sn = 1
        acdc = ''
        state = ''
        bsn = 0
        bd = ''
        blinder0 = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn,
                                 bound=True, bsn=bsn, bd=bd)
        sn = 2
        acdc = 'EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M'  # bob project report ACDC
        state = 'issued'
        bsn = 2
        bd = "EJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv"
        blinder1 = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn,
                                 bound=True, bsn=bsn, bd=bd)
        # enclose and extend with quadlet counter,
        aims = Blinder.enclose([blinder0, blinder1]) #enclose defaults to V2
        msgs.extend(aims)

        # add TypedMediaQuadruples
        crew = TypeMedia(d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE',
                         u='0ABtZWRpYXJyYXdub25jZV8w',
                         mt='application/json',
                         mv='{"name":"Sue","food":"Pizza"}')

        mediar = Mediar(crew=crew)
        # enclose and extend with quadlet counter,
        aims = Mediar.enclose([mediar]) #enclose defaults to V2
        msgs.extend(aims)

        # add TypedDigestSealCouples
        verser = Verser(proto='OCSR')
        assert verser.qb64 == 'YOCSRCAA'
        crew = SealKind(t=verser.qb64, d='EHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE')
        sealer = Sealer(crew=crew)
        assert sealer.qb64 == 'YOCSRCAAEHYFmR_QWCLz8gZyhc4BQ8xJ-ftZ6OA4fNmuu1ZAvyTE'
        # enclose and extend with quadlet counter,
        aims = Sealer.enclose([sealer]) #enclose defaults to V2
        msgs.extend(aims)

        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger0], db=conDB)

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[1].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[1].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))


        # Event 2 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[2].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # Event 3 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=3,
                          version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))


        # Event 4 Interaction  with version 1 psvrsn for serder
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=4,
                          version=Vrsn_1_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # Event 5 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[3].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5,
                        version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))


        # Event 6 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=6,
                          version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[4].verfer.qb64],
                        dig=kever.serder.said,
                        sn=7,
                        version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # Event 8 Interaction but already abandoned
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=8,
                          version=Vrsn_2_0)
        #event_digs.append(serder.said)  # bad event so don't append
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        with pytest.raises(ValidationError):  # nulled so reject any more events
            kever.update(serder=serder, sigers=[siger])

        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))


        # Event 8 Rotation override interaction but already abandoned
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[4].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8,
                        version=Vrsn_2_0)
        #event_digs.append(serder.said)  # bad event so don't append
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])

        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # Switch back to version 1,  gvrsn of 1 will fail when serder pvrsn is 2
        #msgs.extend(gvc1.qb64b)

        assert pre == kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(db=valDB)

        parser = Parser(kvy=kevery, version=Vrsn_2_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_2_0
        assert parser.methods == Parser.Methods[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers2[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs


    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """


def test_parser_v2_mix():
    """Test the support functionality for Parser stream processor CESR v2 with
    mix of V1 Events and attachements

    """
    parser = Parser()  # test defaults
    assert parser.genus == GenDex.KERI
    assert parser.version == Vrsn_2_0
    assert parser.methods == Parser.Methods[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.codes == Parser.Codes[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.sucodes == Parser.SUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]
    assert parser.mucodes == Parser.MUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]

    assert not parser.local
    assert parser.ims == bytearray()
    assert parser.framed
    assert not parser.piped
    assert parser.kvy is None
    assert parser.tvy is None
    assert parser.exc is None
    assert parser.rvy is None
    assert parser.vry is None


    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        event_digs = []  # list of event digs in sequence


        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_2_0.major,
                                                     minor=Vrsn_2_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                                version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAACAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_2_0


        # create event stream
        msgs = bytearray()

        # Start stream
        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers2[1].verfer.qb64b).qb64],
                        version=Vrsn_2_0)

        pre = serder.pre

        assert serder.raw == (b'{"v":"KERICAACAAJSONAAEt.","t":"icp","d":"EAAaPtGJw566KVqqKQvVu2GKViXDzQCJWe'
                            b'QWhy4tdujg","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":'
                            b'"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1","n":["EFXI'
                            b'x7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        assert serder.sad == \
        {
            'v': 'KERICAACAAJSONAAEt.',
            't': 'icp',
            'd': 'EAAaPtGJw566KVqqKQvVu2GKViXDzQCJWeQWhy4tdujg',
            'i': 'DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx',
            's': '0',
            'kt': '1',
            'k': ['DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx'],
            'nt': '1',
            'n': ['EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2'],
            'bt': '0',
            'b': [],
            'c': [],
            'a': []
        }

        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0

        event_digs.append(serder.said)
        # extend key event stream with msg
        msgs.extend(serder.raw)


        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs group count quadlets
        aims = bytearray()  # attachment substream
        siger0 = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(siger0.qb64b)
        siger1 = signers2[1].sign(serder.raw, index=1)  # return siger
        aims.extend(siger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # add witness indexed sigs
        aims = bytearray()  # attachment substream
        wiger0 = signers2[0].sign(serder.raw, index=0)  # return wiger
        aims.extend(wiger0.qb64b)
        wiger1 = signers2[1].sign(serder.raw, index=1)  # return wiger
        aims.extend(wiger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.WitnessIdxSigs))

        # add non trans receipt couples
        aims = bytearray()  # attachment substream
        cigar0 = nsigners2[0].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar0.verfer.qb64b)
        aims.extend(cigar0.qb64b)
        cigar1 = nsigners2[1].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar1.verfer.qb64b)
        aims.extend(cigar1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.NonTransReceiptCouples))

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(tiger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptQuadruples))

        # add Trans Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransIdxSigGroups))

        # add Trans Last Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransLastIdxSigGroups))

        # add first seen replay couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.FirstSeenReplayCouples))

        # add seal source couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceCouples))

        # add seal source triple
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceTriples))

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=pms, code=Codens.PathedMaterialCouples))

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=pms, code=Codens.BigPathedMaterialCouples))

        # add ESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ESSRPayloadGroup))

        # add BigESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeBigEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.BigESSRPayloadGroup))

        # create key event verifier state
        kever = Kever(serder=serder, sigers=[siger0], db=conDB)


        msgs.extend(gvc1.qb64b)  # Switch to version 1
        # setting CESR to V1 which sets serder.gvrsn will fail serder.verify()
        # when serder pvrsn is 2

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[1].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers2[1].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        msgs.extend(gvc2.qb64b)  # Switch to version 2

        # Event 2 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[2].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # Event 3 Interaction  event is V1 attachements V2
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=3)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        msgs.extend(gvc1.qb64b)  # Switch to version 1

        # Event 4 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=4)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)


        msgs.extend(gvc2.qb64b)  # Switch to version 2

        # Event 5 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                    keys=[signers2[3].verfer.qb64],
                    dig=kever.serder.said,
                    ndigs=[coring.Diger(ser=signers2[4].verfer.qb64b).qb64],
                    sn=5,
                    version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))


        # Event 6 Interaction  V1 event but with V2 gvrsn so error kills stream
        #serder = interact(pre=kever.prefixer.qb64,
                          #dig=kever.serder.said,
                          #sn=6,
                          #version=Vrsn_1_0)
        ##event_digs.append(serder.said)
        ## sign serialization
        #siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        ## update key event verifier state
        ##kever.update(serder=serder, sigers=[siger])
        #msgs.extend(serder.raw)  # extend key event stream
        ## Attachments
        #aims = bytearray()
        #aims.extend(siger.qb64b)
        #msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # Event 6 again but V2
        serder = interact(pre=kever.prefixer.qb64,
                              dig=kever.serder.said,
                              sn=6,
                              version=Vrsn_2_0)
        event_digs.append(serder.said)
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # update key event verifier state
        kever.update(serder=serder, sigers=[siger])
        msgs.extend(serder.raw)  # extend key event stream
        # Attachments
        aims = bytearray()
        aims.extend(siger.qb64b)
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        msgs.extend(gvc1.qb64b)  # Switch to version 1

        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[4].verfer.qb64],
                        dig=kever.serder.said,
                        sn=7)
        event_digs.append(serder.said)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)
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
        siger = signers2[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nulled so reject any more events
            kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        # Event 8 Rotation override interaction but already abandoned
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers2[4].verfer.qb64],
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8)
        # create sig counter
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)
        # update key event verifier state
        with pytest.raises(ValidationError):  # nontransferable so reject update
            kever.update(serder=serder, sigers=[siger])
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        #assert len(msgs) == 3745
        #assert len(msgs) == 3833

        assert pre == kever.prefixer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kever.db.getKelIter(pre)]
        assert db_digs == event_digs

        kevery = Kevery(db=valDB)

        parser = Parser(kvy=kevery, version=Vrsn_2_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_2_0
        assert parser.methods == Parser.Methods[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers2[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs


    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """


def test_parser_v2_enclosed_attachments():
    """Test the support functionality for Parser stream processor with CESRv2
    with versioned and enclosed attachments

    """

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:


        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                                     version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_2_0.major,
                                                     minor=Vrsn_2_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAACAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_2_0

        # create event stream
        msgs = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers2[1].verfer.qb64b).qb64],
                        version=Vrsn_2_0)

        pre = serder.pre

        assert serder.raw == (b'{"v":"KERICAACAAJSONAAEt.","t":"icp","d":"EAAaPtGJw566KVqqKQvVu2GKViXDzQCJWe'
                            b'QWhy4tdujg","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":'
                            b'"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1","n":["EFXI'
                            b'x7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0

        # extend key event stream with msg
        msgs.extend(serder.raw)

        # eventually enclose all attachments in AttachmentGroup
        emas = bytearray()  # enclosed message attachment stream
        # put first code in attachments as genus-version counters
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group

        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs group count quadlets
        aims = bytearray()  # attachment substream
        siger0 = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(siger0.qb64b)
        siger1 = signers2[1].sign(serder.raw, index=1)  # return siger
        aims.extend(siger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # add witness indexed sigs
        aims = bytearray()  # attachment substream
        wiger0 = signers2[0].sign(serder.raw, index=0)  # return wiger
        aims.extend(wiger0.qb64b)
        wiger1 = signers2[1].sign(serder.raw, index=1)  # return wiger
        aims.extend(wiger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.WitnessIdxSigs))

        # add non trans receipt couples
        aims = bytearray()  # attachment substream
        cigar0 = nsigners2[0].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar0.verfer.qb64b)
        aims.extend(cigar0.qb64b)
        cigar1 = nsigners2[1].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar1.verfer.qb64b)
        aims.extend(cigar1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.NonTransReceiptCouples))

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(tiger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptQuadruples))

        # add Trans Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransIdxSigGroups))

        # add Trans Last Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransLastIdxSigGroups))

        # add first seen replay couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.FirstSeenReplayCouples))

        # add seal source couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceCouples))

        # add seal source triple
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceTriples))

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.PathedMaterialCouples))

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.BigPathedMaterialCouples))

        # add ESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ESSRPayloadGroup))

        # add BigESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeBigEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.BigESSRPayloadGroup))

        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))


        # Event 1 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers2[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        version=Vrsn_2_0)
        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[1].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))


        # Event 2 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers2[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        version=Vrsn_2_0)
        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))


        # Event 3 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3,
                          version=Vrsn_2_0)
        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))



        # Event 4 Interaction  with version 1 psvrsn for serder
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4,
                          version=Vrsn_1_0)
        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))


        # Event 5 Rotation Transferable
        serder = rotate(pre=pre,
                        keys=[signers2[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5,
                        version=Vrsn_2_0)
        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))



        # Event 6 Interaction
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6,
                          version=Vrsn_2_0)
        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))


        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        sn=7,
                        version=Vrsn_2_0)

        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))

        # Event 8 Interaction but already abandoned
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8,
                          version=Vrsn_2_0)

        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))


        # Event 8 Rotation override interaction but already abandoned
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8,
                        version=Vrsn_2_0)

        msgs.extend(serder.raw)  # extend key event stream
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        emas = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.AttachmentGroup))


        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery)  # default is Vrsn_2_0_
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_2_0
        assert parser.version == Vrsn_2_0
        assert parser.methods == Parser.Methods[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_2_0.major][Vrsn_2_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        oldversion = parser.version

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert parser.version == oldversion
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """



def test_parser_v2_enclosed_message():
    """Test the support functionality for Parser stream processor V2 and Mix
    with versioned and enclosed message+attachments group
    """

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        # put as genus-version counter first in BodyWithAttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                           version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_2_0.major,
                                                     minor=Vrsn_2_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAACAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_2_0

        # create event stream
        msgs = bytearray()
        msgs.extend(gvc2.qb64b)  # set genus-version code at top-level to v2

        # eventually enclose message plus attachments in BodyWithAttachmentGroup
        # put genus-version at front of BodyWithAttachmentGroup substream
        # do not enclose attachments separately
        emas = bytearray()  # enclosed message+attachment stream
        emas.extend(gvc2.qb64b)  # add genus-version code at front of message+attach group
        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers2[1].verfer.qb64b).qb64])
        pre = serder.pre
        assert serder.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs group count quadlets
        siger0 = signers2[0].sign(serder.raw, index=0)  # return siger
        siger1 = signers2[1].sign(serder.raw, index=1)  # return siger
        # attachments
        aims = bytearray()  # attachment substream
        aims.extend(siger0.qb64b)
        aims.extend(siger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # add witness indexed sigs
        wiger0 = signers2[0].sign(serder.raw, index=0)  # return wiger
        wiger1 = signers2[1].sign(serder.raw, index=1)  # return wiger
        aims = bytearray()  # attachment substream
        aims.extend(wiger0.qb64b)
        aims.extend(wiger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.WitnessIdxSigs))

        # add non trans receipt couples
        aims = bytearray()  # attachment substream
        cigar0 = nsigners2[0].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar0.verfer.qb64b)
        aims.extend(cigar0.qb64b)
        cigar1 = nsigners2[1].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar1.verfer.qb64b)
        aims.extend(cigar1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.NonTransReceiptCouples))

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(tiger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptQuadruples))

        # add Trans Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransIdxSigGroups))

        # add Trans Last Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransLastIdxSigGroups))

        # add first seen replay couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.FirstSeenReplayCouples))

        # add seal source couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceCouples))

        # add seal source triple
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceTriples))

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.PathedMaterialCouples))

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.BigPathedMaterialCouples))

        # add ESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ESSRPayloadGroup))

        # add BigESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeBigEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.BigESSRPayloadGroup))

        # enclose  message attachements and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        # Event 1 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in message-attachment group
        serder = rotate(pre=pre,
                        keys=[signers2[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[1].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 2 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc1.qb64b)  # V1 message insize v1 message group
        serder = rotate(pre=pre,
                        keys=[signers2[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        version=Vrsn_1_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_1_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group  V1 that overrides to V2
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas use V1 attachment group
        emas.extend(Counter.enclose(qb64=eims,
                                    code=Codens.AttachmentGroup,
                                    version=Vrsn_1_0))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 3 Interaction  default V2 set at top level
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))



        # Event 4 Interaction  with version 2 serder and V1 attachements
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachments
        aims = bytearray()  # enclosed message attachment stream
        aims.extend(gvc1.qb64b)  # insert genus-version V1 code in attachment group
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        aims.extend(siger.qb64b)
        # enclose  message attachements with v2 counter
        emas.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup))
        # enclose message plus attachments with v2
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 5 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5,
                        version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))



        # Event 6 Interaction
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        sn=7,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8,
                          version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Rotation override interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)  # default v1 but override at top level above
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]

        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)
        assert msgs == bytearray(b'')  # emptied
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """

def test_parse_generic_group():
    """Test parse with nested GenericGroups """

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        # put as genus-version counter first in BodyWithAttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                           version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_2_0.major,
                                                     minor=Vrsn_2_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAACAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_2_0

        # create toplevel stream
        msgs = bytearray()
        msgs.extend(gvc2.qb64b)  # set genus-version code at top-level to v2

        # create generic group sub stream
        ggms = bytearray()
        ggms.extend(gvc2.qb64b)  # set genus-version code at outer most generic

        # eventually enclose message plus attachments in BodyWithAttachmentGroup
        # put genus-version at front of BodyWithAttachmentGroup substream
        # do not enclose attachments separately
        emas = bytearray()  # enclosed message+attachment stream
        emas.extend(gvc2.qb64b)  # add genus-version code at front of message+attach group
        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers2[1].verfer.qb64b).qb64])
        pre = serder.pre
        assert serder.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs group count quadlets
        siger0 = signers2[0].sign(serder.raw, index=0)  # return siger
        siger1 = signers2[1].sign(serder.raw, index=1)  # return siger
        # attachments
        aims = bytearray()  # attachment substream
        aims.extend(siger0.qb64b)
        aims.extend(siger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # add witness indexed sigs
        wiger0 = signers2[0].sign(serder.raw, index=0)  # return wiger
        wiger1 = signers2[1].sign(serder.raw, index=1)  # return wiger
        aims = bytearray()  # attachment substream
        aims.extend(wiger0.qb64b)
        aims.extend(wiger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.WitnessIdxSigs))

        # add non trans receipt couples
        aims = bytearray()  # attachment substream
        cigar0 = nsigners2[0].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar0.verfer.qb64b)
        aims.extend(cigar0.qb64b)
        cigar1 = nsigners2[1].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar1.verfer.qb64b)
        aims.extend(cigar1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.NonTransReceiptCouples))

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(tiger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptQuadruples))

        # add Trans Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransIdxSigGroups))

        # add Trans Last Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransLastIdxSigGroups))

        # add first seen replay couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.FirstSeenReplayCouples))

        # add seal source couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceCouples))

        # add seal source triple
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceTriples))

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.PathedMaterialCouples))

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.BigPathedMaterialCouples))

        # add ESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ESSRPayloadGroup))

        # add BigESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeBigEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.BigESSRPayloadGroup))

        # enclose  message attachements and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        ngms0 = bytearray()  # nested generic group
        ngms1 = bytearray()  # coubly nested generic group
        # Event 1 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in message-attachment group
        serder = rotate(pre=pre,
                        keys=[signers2[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[1].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to
        ngms1.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ngms0.extend(Counter.enclose(qb64=ngms1, code=Codens.GenericGroup))

        # Event 2 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc1.qb64b)  # V1 message insize v1 message group
        serder = rotate(pre=pre,
                        keys=[signers2[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        version=Vrsn_1_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_1_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group  V1 that overrides to V2
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas use V1 attachment group
        emas.extend(Counter.enclose(qb64=eims,
                                    code=Codens.AttachmentGroup,
                                    version=Vrsn_1_0))
        # enclose message + attachments and add to enclosing group
        ngms0.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ggms.extend(Counter.enclose(qb64=ngms0, code=Codens.GenericGroup))


        # Event 3 Interaction  default V2 set at top level
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        ngms0 = bytearray()
        # Event 4 Interaction  with version 2 serder and V1 attachements
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachments
        aims = bytearray()  # enclosed message attachment stream
        aims.extend(gvc1.qb64b)  # insert genus-version V1 code in attachment group
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        aims.extend(siger.qb64b)
        # enclose  message attachements with v2 counter
        emas.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup))
        # enclose message plus attachments with v2
        ngms0.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ggms.extend(Counter.enclose(qb64=ngms0, code=Codens.GenericGroup))



        # Event 5 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5,
                        version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        # Event 6 Interaction
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        sn=7,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8,
                          version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Rotation override interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to outermost generic
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        # enclose outermost generic and add to top level stream
        msgs.extend(Counter.enclose(qb64=ggms, code=Codens.GenericGroup))

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)  # default v1 but override at top level above
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)  # version 1 default changes to v2 in stream top level
        assert msgs == bytearray(b'')  # emptied
        assert parser.version == Vrsn_2_0  # changed top level version in stream
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """


def test_group_parsator():
    """Test groupParsator """

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        # put as genus-version counter first in BodyWithAttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                           version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_2_0.major,
                                                     minor=Vrsn_2_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAACAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_2_0

        # create toplevel stream
        msgs = bytearray()
        msgs.extend(gvc2.qb64b)  # set genus-version code at top-level to v2

        # create generic group sub stream
        ggms = bytearray()
        ggms.extend(gvc2.qb64b)  # set genus-version code at outer most generic

        # eventually enclose message plus attachments in BodyWithAttachmentGroup
        # put genus-version at front of BodyWithAttachmentGroup substream
        # do not enclose attachments separately
        emas = bytearray()  # enclosed message+attachment stream
        emas.extend(gvc2.qb64b)  # add genus-version code at front of message+attach group
        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers2[1].verfer.qb64b).qb64])
        pre = serder.pre
        assert serder.raw == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXu'
                        b'zOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIW'
                        b'DiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                        b'AeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJA'
                        b'am69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

        # since enclosed in group must convert serder to texter so aligned on
        # 24 bit boundaries and then include in NonNativeBodyGroup
        # extend key event stream with msg
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs group count quadlets
        siger0 = signers2[0].sign(serder.raw, index=0)  # return siger
        siger1 = signers2[1].sign(serder.raw, index=1)  # return siger
        # attachments
        aims = bytearray()  # attachment substream
        aims.extend(siger0.qb64b)
        aims.extend(siger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # add witness indexed sigs
        wiger0 = signers2[0].sign(serder.raw, index=0)  # return wiger
        wiger1 = signers2[1].sign(serder.raw, index=1)  # return wiger
        aims = bytearray()  # attachment substream
        aims.extend(wiger0.qb64b)
        aims.extend(wiger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.WitnessIdxSigs))

        # add non trans receipt couples
        aims = bytearray()  # attachment substream
        cigar0 = nsigners2[0].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar0.verfer.qb64b)
        aims.extend(cigar0.qb64b)
        cigar1 = nsigners2[1].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar1.verfer.qb64b)
        aims.extend(cigar1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.NonTransReceiptCouples))

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(tiger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptQuadruples))

        # add Trans Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransIdxSigGroups))

        # add Trans Last Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransLastIdxSigGroups))

        # add first seen replay couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.FirstSeenReplayCouples))

        # add seal source couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceCouples))

        # add seal source triple
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceTriples))

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.PathedMaterialCouples))

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.BigPathedMaterialCouples))

        # add ESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ESSRPayloadGroup))

        # add BigESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeBigEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.BigESSRPayloadGroup))

        # enclose  message attachements and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        ngms0 = bytearray()  # nested generic group
        ngms1 = bytearray()  # coubly nested generic group
        # Event 1 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in message-attachment group
        serder = rotate(pre=pre,
                        keys=[signers2[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[1].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to
        ngms1.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ngms0.extend(Counter.enclose(qb64=ngms1, code=Codens.GenericGroup))

        # Event 2 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc1.qb64b)  # V1 message insize v1 message group
        serder = rotate(pre=pre,
                        keys=[signers2[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        version=Vrsn_1_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_1_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group  V1 that overrides to V2
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas use V1 attachment group
        emas.extend(Counter.enclose(qb64=eims,
                                    code=Codens.AttachmentGroup,
                                    version=Vrsn_1_0))
        # enclose message + attachments and add to enclosing group
        ngms0.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ggms.extend(Counter.enclose(qb64=ngms0, code=Codens.GenericGroup))


        # Event 3 Interaction  default V2 set at top level
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        ngms0 = bytearray()
        # Event 4 Interaction  with version 2 serder and V1 attachements
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachments
        aims = bytearray()  # enclosed message attachment stream
        aims.extend(gvc1.qb64b)  # insert genus-version V1 code in attachment group
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        aims.extend(siger.qb64b)
        # enclose  message attachements with v2 counter
        emas.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup))
        # enclose message plus attachments with v2
        ngms0.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ggms.extend(Counter.enclose(qb64=ngms0, code=Codens.GenericGroup))



        # Event 5 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5,
                        version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        # Event 6 Interaction
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6,
                          version=Vrsn_2_0)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        sn=7,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8,
                          version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Rotation override interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8,
                        version=Vrsn_2_0)

        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_2_0))
        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to outermost generic
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        # enclose outermost generic and add to top level stream
        msgs.extend(Counter.enclose(qb64=ggms, code=Codens.GenericGroup))

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)  # default v1 but override at top level above
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None


        framed = True
        piped = False
        kvy = kevery
        tvy = None
        exc = None
        rvy = None
        vry = None
        local = False
        version = Vrsn_1_0


        parsator = parser.groupParsator(ims=msgs,
                                        framed=framed,
                                        piped=piped,
                                        kvy=kvy,
                                        tvy=tvy,
                                        exc=exc,
                                        rvy=rvy,
                                        vry=vry,
                                        local=local,
                                        version=version)

        while True:
            try:
                next(parsator)
            except StopIteration:
                break
            except (ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                continue


        assert msgs == bytearray(b'')  # emptied
        assert parser.version == Vrsn_2_0  # changed top level version in stream
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """


def test_parse_native_cesr_fixed_field():
    """Test parse with nested GenericGroups with fixed field KERI messages """

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = core.Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = core.Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        # put as genus-version counter first in BodyWithAttachmentGroup
        gvc1 = Counter(countB64=Counter.verToB64(major=Vrsn_1_0.major,
                                                     minor=Vrsn_1_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                           version=Vrsn_1_0)
        assert gvc1.qb64 == '-_AAABAA'
        assert Counter.b64ToVer(gvc1.countToB64(l=3)) == Vrsn_1_0

        gvc2 = Counter(countB64=Counter.verToB64(major=Vrsn_2_0.major,
                                                     minor=Vrsn_2_0.minor),
                           code=Codens.KERIACDCGenusVersion,
                               version=Vrsn_2_0)
        assert gvc2.qb64 == '-_AAACAA'
        assert Counter.b64ToVer(gvc2.countToB64(l=3)) == Vrsn_2_0

        # create toplevel stream
        msgs = bytearray()
        msgs.extend(gvc2.qb64b)  # set genus-version code at top-level to v2

        # create generic group sub stream
        ggms = bytearray()
        ggms.extend(gvc2.qb64b)  # set genus-version code at outer most generic

        # eventually enclose message plus attachments in BodyWithAttachmentGroup
        # put genus-version at front of BodyWithAttachmentGroup substream
        # do not enclose attachments separately
        emas = bytearray()  # enclosed message+attachment stream
        emas.extend(gvc2.qb64b)  # add genus-version code at front of message+attach group
        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[coring.Diger(ser=signers2[1].verfer.qb64b).qb64],
                        version=Vrsn_2_0, kind=Kinds.cesr)
        pre = serder.pre

        assert serder.raw == (b'-FA50OKERICAACAAXicpEFaYE2LTv8dItUgQzIHKRA9FaHDrHtIHNs-m5DJKWXRNDNG2arBDtHK_'
                            b'JyHRAq-emRdC6UM-yIpCAeJIWDiXp4HxMAAAMAAB-JALDNG2arBDtHK_JyHRAq-emRdC6UM-yIpC'
                            b'AeJIWDiXp4HxMAAB-JALEFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2MAAA-JAA-JAA'
                            b'-JAA')

        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0

        emas.extend(serder.raw)
        # create sig counter for two sigs one is spurious since single sig AID
        # sign serialization indexed controller sigs group count quadlets
        siger0 = signers2[0].sign(serder.raw, index=0)  # return siger
        siger1 = signers2[1].sign(serder.raw, index=1)  # return siger
        # attachments
        aims = bytearray()  # attachment substream
        aims.extend(siger0.qb64b)
        aims.extend(siger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))

        # add witness indexed sigs
        wiger0 = signers2[0].sign(serder.raw, index=0)  # return wiger
        wiger1 = signers2[1].sign(serder.raw, index=1)  # return wiger
        aims = bytearray()  # attachment substream
        aims.extend(wiger0.qb64b)
        aims.extend(wiger1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.WitnessIdxSigs))

        # add non trans receipt couples
        aims = bytearray()  # attachment substream
        cigar0 = nsigners2[0].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar0.verfer.qb64b)
        aims.extend(cigar0.qb64b)
        cigar1 = nsigners2[1].sign(serder.raw)  # return cigar since no index
        aims.extend(cigar1.verfer.qb64b)
        aims.extend(cigar1.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.NonTransReceiptCouples))

        # add trans receipt quadruples  spre+ssnu+sdig+sig
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        aims.extend(tiger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptQuadruples))

        # add Trans Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransIdxSigGroups))

        # add Trans Last Indexed Sig Groups
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        sims = bytearray() # attachment sub-sub-stream
        siger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(siger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransLastIdxSigGroups))

        # add first seen replay couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(Dater(dts='2020-08-22T17:50:09.988921+00:00').qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.FirstSeenReplayCouples))

        # add seal source couple
        aims = bytearray()  # attachment substream
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceCouples))

        # add seal source triple
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.SealSourceTriples))

        # add small PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('Z', 'W'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Should we stop and rest here?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.PathedMaterialCouples))

        # add big PathedMaterialCouples
        pms = bytearray()
        pather = Pather(parts=('K', 'P'))
        pms.extend(pather.qb64b)
        texter = Texter(text=b'Is not that a better spot over there?')
        pms.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=pms, code=Codens.BigPathedMaterialCouples))

        # add ESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.ESSRPayloadGroup))

        # add BigESSRPayloadGroup
        aims = bytearray()  # attachment substream
        texter = Texter(text=b"MeBeBigEssr")
        aims.extend(texter.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.BigESSRPayloadGroup))

        # enclose  message attachements and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        ngms0 = bytearray()  # nested generic group
        ngms1 = bytearray()  # coubly nested generic group
        # Event 1 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in message-attachment group
        serder = rotate(pre=pre,
                        keys=[signers2[1].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        version=Vrsn_2_0,
                        kind=Kinds.cesr)

        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[1].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to
        ngms1.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ngms0.extend(Counter.enclose(qb64=ngms1, code=Codens.GenericGroup))

        # Event 2 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # V2 message inside v2 message group
        serder = rotate(pre=pre,
                        keys=[signers2[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        version=Vrsn_2_0,
                        kind=Kinds.cesr)
        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group  V1 that overrides to V2
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas use V2 attachment group
        emas.extend(Counter.enclose(qb64=eims,
                                    code=Codens.AttachmentGroup,
                                    version=Vrsn_2_0))
        # enclose message + attachments and add to enclosing group
        ngms0.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ggms.extend(Counter.enclose(qb64=ngms0, code=Codens.GenericGroup))


        # Event 3 Interaction  default V2 set at top level
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3,
                          version=Vrsn_2_0,
                          kind=Kinds.cesr)
        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachment group
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        ngms0 = bytearray()
        # Event 4 Interaction  with version 2 serder and V1 attachements
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4,
                          version=Vrsn_2_0,
                          kind=Kinds.cesr)

        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # Attachments
        aims = bytearray()  # enclosed message attachment stream
        aims.extend(gvc1.qb64b)  # insert genus-version V1 code in attachment group
        counter = Counter(Codens.ControllerIdxSigs, version=Vrsn_1_0)  # default is count = 1
        aims.extend(counter.qb64b)
        aims.extend(siger.qb64b)
        # enclose  message attachments with v2 counter
        emas.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup))
        # enclose message plus attachments with v2
        ngms0.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        ggms.extend(Counter.enclose(qb64=ngms0, code=Codens.GenericGroup))



        # Event 5 Rotation Transferable
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5,
                        version=Vrsn_2_0,
                        kind=Kinds.cesr)
        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))

        # Event 6 Interaction
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6,
                          version=Vrsn_2_0,
                          kind=Kinds.cesr)
        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[3].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 7 Rotation to null NonTransferable Abandon
        # nxt digest is empty
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        sn=7,
                        version=Vrsn_2_0,
                        kind=Kinds.cesr)

        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=8,
                          version=Vrsn_2_0,
                          kind=Kinds.cesr)

        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to enclosing group
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 8 Rotation override interaction but already abandoned
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[4].verfer.qb64],
                        dig=serder.said,
                        ndigs=[coring.Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8,
                        version=Vrsn_2_0,
                        kind=Kinds.cesr)

        emas.extend(serder.raw)

        # sign serialization
        siger = signers2[4].sign(serder.raw, index=0)  # returns siger
        # Attachments
        eims = bytearray()  # enclosed message attachment stream
        aims = bytearray()
        aims.extend(siger.qb64b)
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas
        emas.extend(Counter.enclose(qb64=eims, code=Codens.AttachmentGroup))
        # enclose message + attachments and add to outermost generic
        ggms.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))
        # enclose outermost generic and add to top level stream
        msgs.extend(Counter.enclose(qb64=ggms, code=Codens.GenericGroup))

        kevery = Kevery(db=valDB)
        parser = Parser(kvy=kevery, version=Vrsn_1_0)  # default v1 but override at top level above
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_1_0
        assert parser.methods == Parser.Methods[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.codes == Parser.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.sucodes == Parser.SUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.mucodes == Parser.MUCodes[Vrsn_1_0.major][Vrsn_1_0.minor]
        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None

        parser.parse(ims=msgs)  # version 1 default changes to v2 in stream top level
        assert msgs == bytearray(b'')  # emptied
        assert parser.version == Vrsn_2_0  # changed top level version in stream
        assert serder.pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 7

    assert not os.path.exists(kevery.db.path)

    """ Done Test """


if __name__ == "__main__":
    test_parser_v1_basic()
    test_parser_v1_version()
    test_parser_v1_enclosed_attachments()
    test_parser_v1_enclosed_message()
    test_parser_v1_non_native_message()
    test_parser_v2_basic()
    test_parser_v2_mix()
    test_parser_v2_enclosed_attachments()
    test_parser_v2_enclosed_message()
    test_parse_generic_group()
    test_group_parsator()
    test_parse_native_cesr_fixed_field()
