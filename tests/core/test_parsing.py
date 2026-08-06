# -*- encoding: utf-8 -*-
"""
tests.core.test_parsing module

"""
import os
from collections import deque
from dataclasses import asdict

import pytest

from hio.help import ogler


from keri.kering import (ValidationError, Vrsn_1_0, Vrsn_2_0, Kinds,
                         ExtractionError, ShortageError, OutOfOrderError)
from keri.core.parsing import Fault, Disps, faultKind

from keri.core import (Counter, Diger, GenDex, Codens, Seqner, Dater, Texter, Pather,
                       Blinder, Mediar, TypeMedia, Sealer, SealKind, Verser,
                       Salter, Parser, Kever, Kevery, incept, rotate, interact,
                       exchept, messagize)

from keri.db import openDB


logger = ogler.getLogger()

V1_KWA = dict(version=Vrsn_1_0, kind=Kinds.json)
V2_KWA = dict(version=Vrsn_2_0, kind=Kinds.json)
V2_CESR_KWA = dict(version=Vrsn_2_0, kind=Kinds.cesr)


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
    signers = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners = Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        event_digs = []  # list of event digs in sequence

        # create event stream
        msgs = bytearray()

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **V1_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #counter = Counter(Codens.TransReceiptIdxSigGroups, count=1, version=Vrsn_1_0)
        #msgs.extend(counter.qb64b)
        #msgs.extend(serder.pre.encode())
        #msgs.extend(Seqner(snh=serder.snh).qb64b)
        #msgs.extend(serder.said.encode())
        #tiger = signers[0].sign(serder.raw, index=0)  # return siger
        #msgs.extend(tiger.qb64b)

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers[0].sign(serder.raw, index=0)  # return siger
        # v1 content counter not quadlet counter
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        sims.extend(counter.qb64b)
        sims.extend(riger.qb64b)
        aims.extend(sims)
        # enclose and extend with quadlet counter v1
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups, version=Vrsn_1_0))

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
                        ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1, **V1_KWA)
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
                        ndigs=[Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2, **V1_KWA)
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
                          sn=3, **V1_KWA)
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
                          sn=4, **V1_KWA)
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
                        ndigs=[Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5, **V1_KWA)
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
                          sn=6, **V1_KWA)
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
                        sn=7, **V1_KWA)
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
                          sn=8, **V1_KWA)
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
                        ndigs=[Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8, **V1_KWA)
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

        db_digs = [val for val in kever.db.kels.getAllIter(keys=pre)]
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

        result = parser.parse(ims=msgs)
        assert result == True
        assert msgs == bytearray(b'')  # emptied
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [val for val in kevery.db.kels.getAllIter(keys=pre)]
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
    signers1 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners1 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers1[1].verfer.qb64b).qb64], **V1_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #counter = Counter(Codens.TransReceiptIdxSigGroups, count=1, version=Vrsn_1_0)
        #msgs.extend(counter.qb64b)
        #msgs.extend(serder.pre.encode())
        #msgs.extend(Seqner(snh=serder.snh).qb64b)
        #msgs.extend(serder.said.encode())
        #tiger = signers1[0].sign(serder.raw, index=0)  # return siger
        #msgs.extend(tiger.qb64b)

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers1[0].sign(serder.raw, index=0)  # return siger
        # v1 content counter not quadlet counter
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        sims.extend(counter.qb64b)
        sims.extend(riger.qb64b)
        aims.extend(sims)
        # enclose and extend with quadlet counter v1
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups, version=Vrsn_1_0))

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
    signers = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners = Salter(raw=raw).signers(count=8,
                                            path='psr',
                                            temp=True,
                                            transferable=False)


    with openDB(name="controller") as conDB, openDB(name="validator") as valDB:
        # create event stream
        msgs = bytearray()


        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **V1_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #counter = Counter(Codens.TransReceiptIdxSigGroups, count=1, version=Vrsn_1_0)
        #emas.extend(counter.qb64b)
        #emas.extend(serder.pre.encode())
        #emas.extend(Seqner(snh=serder.snh).qb64b)
        #emas.extend(serder.said.encode())
        #tiger = signers[0].sign(serder.raw, index=0)  # return siger
        #emas.extend(tiger.qb64b)

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers[0].sign(serder.raw, index=0)  # return siger
        # v1 content counter not quadlet counter
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        sims.extend(counter.qb64b)
        sims.extend(riger.qb64b)
        aims.extend(sims)
        # enclose and extend with quadlet counter v1
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups, version=Vrsn_1_0))

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
                        ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1, **V1_KWA)

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
                        ndigs=[Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2, **V1_KWA)

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
                          sn=3, **V1_KWA)

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
                          sn=4, **V1_KWA)

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
                        ndigs=[Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5, **V1_KWA)

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
                          sn=6, **V1_KWA)

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
                        sn=7, **V1_KWA)

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
                          sn=8, **V1_KWA)
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
                        ndigs=[Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8, **V1_KWA)
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
    signers = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **V1_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #counter = Counter(Codens.TransReceiptIdxSigGroups, count=1, version=Vrsn_1_0)
        #eims.extend(counter.qb64b)
        #eims.extend(serder.pre.encode())
        #eims.extend(Seqner(snh=serder.snh).qb64b)
        #eims.extend(serder.said.encode())
        #tiger = signers[0].sign(serder.raw, index=0)  # return siger
        #eims.extend(tiger.qb64b)

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers[0].sign(serder.raw, index=0)  # return siger
        # v1 content counter not quadlet counter
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        sims.extend(counter.qb64b)
        sims.extend(riger.qb64b)
        aims.extend(sims)
        # enclose and extend with quadlet counter v1
        eims.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups, version=Vrsn_1_0))

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
                        ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1, **V1_KWA)

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
                        ndigs=[Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2, **V1_KWA)

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
                          sn=3, **V1_KWA)

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
                          sn=4, **V1_KWA)

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
                        ndigs=[Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5, **V1_KWA)

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
                          sn=6, **V1_KWA)

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
                        sn=7, **V1_KWA)

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
                          sn=8, **V1_KWA)
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
                        ndigs=[Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8, **V1_KWA)
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
    signers = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **V1_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #counter = Counter(Codens.TransReceiptIdxSigGroups, count=1, version=Vrsn_1_0)
        #msgs.extend(counter.qb64b)
        #msgs.extend(serder.pre.encode())
        #msgs.extend(Seqner(snh=serder.snh).qb64b)
        #msgs.extend(serder.said.encode())
        #tiger = signers[0].sign(serder.raw, index=0)  # return siger
        #msgs.extend(tiger.qb64b)

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers[0].sign(serder.raw, index=0)  # return siger
        # v1 content counter not quadlet counter
        counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)
        sims.extend(counter.qb64b)
        sims.extend(riger.qb64b)
        aims.extend(sims)
        # enclose and extend with quadlet counter v1
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups, version=Vrsn_1_0))


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
                        ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
                        sn=1, **V1_KWA)

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
                        ndigs=[Diger(ser=signers[3].verfer.qb64b).qb64],
                        sn=2, **V1_KWA)

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
                          sn=3, **V1_KWA)

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
                          sn=4, **V1_KWA)

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
                        ndigs=[Diger(ser=signers[4].verfer.qb64b).qb64],
                        sn=5, **V1_KWA)

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
                          sn=6, **V1_KWA)

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
                        sn=7, **V1_KWA)

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
                          sn=8, **V1_KWA)
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
                        ndigs=[Diger(ser=signers[5].verfer.qb64b).qb64],
                        sn=8, **V1_KWA)
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
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64], **V2_KWA)

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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #aims = bytearray()  # attachment substream
        #aims.extend(serder.pre.encode())
        #aims.extend(Seqner(snh=serder.snh).qb64b)
        #aims.extend(serder.said.encode())
        #tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        #aims.extend(tiger.qb64b)
        ## enclose and extend with quadlet counter, enclose defaults to V2
        #msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(riger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add Trans Indexed Sig Groups  spre+ssnu+sdig+[sigs]
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
        acdc = 'EP-iKGmXD-iZu3RhVA2FTI-dOdX50bRBV3VDCy-peOtv'  # bob project report ACDC
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
        acdc = 'EP-iKGmXD-iZu3RhVA2FTI-dOdX50bRBV3VDCy-peOtv'  # bob project report ACDC
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
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1, **V2_KWA)
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
                        ndigs=[Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2, **V2_KWA)
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
                          sn=3, **V2_KWA)
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
                          **V1_KWA)
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
                        ndigs=[Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5, **V2_KWA)
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
                          sn=6, **V2_KWA)
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
                        sn=7, **V2_KWA)
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
                          sn=8, **V2_KWA)
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
                        ndigs=[Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8, **V2_KWA)
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

        assert pre == kever.prefixer.qb64

        db_digs = [val for val in kever.db.kels.getAllIter(keys=pre)]
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

        db_digs = [val for val in kevery.db.kels.getAllIter(keys=pre)]
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
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64], **V2_KWA)

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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #aims = bytearray()  # attachment substream
        #aims.extend(serder.pre.encode())
        #aims.extend(Seqner(snh=serder.snh).qb64b)
        #aims.extend(serder.said.encode())
        #tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        #aims.extend(tiger.qb64b)
        ## enclose and extend with quadlet counter, enclose defaults to V2
        #msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(riger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        msgs.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

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
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        **V1_KWA)
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
                        ndigs=[Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2, **V2_KWA)
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
                          sn=3,
                          **V1_KWA)
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
                          sn=4,
                          **V1_KWA)
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
                    ndigs=[Diger(ser=signers2[4].verfer.qb64b).qb64],
                    sn=5, **V2_KWA)
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
                          #**V1_KWA)
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
                              sn=6, **V2_KWA)
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
                        sn=7,
                        **V1_KWA)
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
                          sn=8,
                          **V1_KWA)
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
                        ndigs=[Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8,
                        **V1_KWA)
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

        db_digs = [val for val in kever.db.kels.getAllIter(keys=pre)]
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

        db_digs = [val for val in kevery.db.kels.getAllIter(keys=pre)]
        assert db_digs == event_digs


    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """


def test_parser_v2_enclosed_attachments():
    """Test the support functionality for Parser stream processor with CESRv2
    and v1 mix but all with versioned and enclosed attachments

    """

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64], **V2_KWA)

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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #aims = bytearray()  # attachment substream
        #aims.extend(serder.pre.encode())
        #aims.extend(Seqner(snh=serder.snh).qb64b)
        #aims.extend(serder.said.encode())
        #tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        #aims.extend(tiger.qb64b)
        ## enclose and extend with quadlet counter, enclose defaults to V2
        #emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(riger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

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
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1, **V2_KWA)
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
                        ndigs=[Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2, **V2_KWA)
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
                          sn=3, **V2_KWA)
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

        # Event 4 Interaction  with version 1 psvrsn for serder but attachments
        # use gvrsn of stream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4,
                          **V1_KWA)
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
                        ndigs=[Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5, **V2_KWA)
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
                          sn=6, **V2_KWA)
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
                        sn=7, **V2_KWA)

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
                          sn=8, **V2_KWA)

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
                        ndigs=[Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8, **V2_KWA)

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
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64], **V2_KWA)
        pre = serder.pre
        assert serder.raw == (b'{"v":"KERICAACAAJSONAAEt.","t":"icp","d":"EAAaPtGJw566KVqqKQvVu2GKViXDzQCJWe'
                            b'QWhy4tdujg","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":'
                            b'"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1","n":["EFXI'
                            b'x7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}')

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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #aims = bytearray()  # attachment substream
        #aims.extend(serder.pre.encode())
        #aims.extend(Seqner(snh=serder.snh).qb64b)
        #aims.extend(serder.said.encode())
        #tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        #aims.extend(tiger.qb64b)
        ## enclose and extend with quadlet counter, enclose defaults to V2
        #emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(riger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

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
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1, **V2_KWA)

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


        # Event 2 Rotation Transferable v1 serder inside v1 group body+attach
        # prepend stream genus code override to force stream to v1 so can use v1 group
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc1.qb64b)  # V1 message inside v1 message group
        serder = rotate(pre=pre,
                        keys=[signers2[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        **V1_KWA)
        texter = Texter(raw=serder.raw)
        emas.extend(Counter.enclose(qb64=texter.qb64b,
                                    code=Codens.NonNativeBodyGroup,
                                    version=Vrsn_1_0))
        # sign serialization
        siger = signers2[2].sign(serder.raw, index=0)  # returns siger
        # genus  V2 that overrides v1 for attach group inside v1 body + attach group
        eims = bytearray()  # enclosed message attachment stream
        eims.extend(gvc2.qb64b)  # insert genus-version V2 code in attachment group
        aims = bytearray()
        aims.extend(siger.qb64b)
        # v2 idxsigs group
        eims.extend(Counter.enclose(qb64=aims, code=Codens.ControllerIdxSigs))
        # enclose  attachments and add to emas use V1 attachment group inside
        # v1 attach group inside v2 body+attachment group with v1 genus override
        emas.extend(Counter.enclose(qb64=eims,
                                    code=Codens.AttachmentGroup,
                                    version=Vrsn_1_0))
        # enclose message + attachments and add to msgs
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 3 Interaction  with v2 serder and v2 body attachments
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=3, **V2_KWA)
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

        # Event 4 Interaction  with version 2 serder and V1 override attachements
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc2.qb64b)  # insert genus-version V2 code override in body group
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=4, **V2_KWA)
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
        # enclose  message attachements with v2 counter inside v2 body+attach group
        emas.extend(Counter.enclose(qb64=aims, code=Codens.AttachmentGroup))
        # enclose message plus attachments with v2
        msgs.extend(Counter.enclose(qb64=emas, code=Codens.BodyWithAttachmentGroup))


        # Event 5 Rotation Transferable all v2
        emas = bytearray()  # message + attachement substream
        serder = rotate(pre=pre,
                        keys=[signers2[3].verfer.qb64],
                        dig=serder.said,
                        ndigs=[Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5, **V2_KWA)
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


        # Event 6 Interaction all v2
        emas = bytearray()  # message + attachement substream
        serder = interact(pre=pre,
                          dig=serder.said,
                          sn=6, **V2_KWA)
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
                        sn=7, **V2_KWA)

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
                          sn=8, **V2_KWA)

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
                        ndigs=[Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8, **V2_KWA)

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
    """Test parse with nested GenericGroups with v1 v2 mix"""

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64], **V1_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #aims = bytearray()  # attachment substream
        #aims.extend(serder.pre.encode())
        #aims.extend(Seqner(snh=serder.snh).qb64b)
        #aims.extend(serder.said.encode())
        #tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        #aims.extend(tiger.qb64b)
        ## enclose and extend with quadlet counter, enclose defaults to V2
        #emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(riger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

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
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1, **V2_KWA)

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

        # Event 2 Rotation Transferable v1 override body, v2 override attach
        emas = bytearray()  # message + attachement substream
        emas.extend(gvc1.qb64b)  # V1 message inside v1 override in message group
        serder = rotate(pre=pre,
                        keys=[signers2[2].verfer.qb64],
                        dig=serder.said,
                        ndigs=[Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        **V1_KWA)
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
                          sn=3, **V2_KWA)
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
                          sn=4, **V2_KWA)
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
                        ndigs=[Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5, **V2_KWA)
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
                          sn=6, **V2_KWA)
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
                        sn=7, **V2_KWA)

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
                          sn=8, **V2_KWA)

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
                        ndigs=[Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8, **V2_KWA)

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
    """Test groupParsator with mix v1 v2"""

    logger.setLevel("ERROR")

    #  create transferable signers
    raw = b"ABCDEFGH01234567"
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64], **V1_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #aims = bytearray()  # attachment substream
        #aims.extend(serder.pre.encode())
        #aims.extend(Seqner(snh=serder.snh).qb64b)
        #aims.extend(serder.said.encode())
        #tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        #aims.extend(tiger.qb64b)
        ## enclose and extend with quadlet counter, enclose defaults to V2
        #emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(riger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

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
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1, **V2_KWA)

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
                        ndigs=[Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2,
                        **V1_KWA)
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
                          sn=3, **V2_KWA)
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
                          sn=4, **V2_KWA)
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
                        ndigs=[Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5, **V2_KWA)
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
                          sn=6, **V2_KWA)
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
                        sn=7, **V2_KWA)

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
                          sn=8, **V2_KWA)

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
                        ndigs=[Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8, **V2_KWA)

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
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)

    # create non-transferable signers
    raw = b"abcdefghijklmnop"
    nsigners2 = Salter(raw=raw).signers(count=8,
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
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64],
                        **V2_CESR_KWA)
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

        ## add trans receipt quadruples  spre+ssnu+sdig+sig
        #aims = bytearray()  # attachment substream
        #aims.extend(serder.pre.encode())
        #aims.extend(Seqner(snh=serder.snh).qb64b)
        #aims.extend(serder.said.encode())
        #tiger = signers2[0].sign(serder.raw, index=0)  # return siger
        #aims.extend(tiger.qb64b)
        ## enclose and extend with quadlet counter, enclose defaults to V2
        #emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

        # add trans receipt idx sig groups  rpre+rsnu+rdig+[rigs]
        aims = bytearray()  # attachment substream
        aims.extend(serder.pre.encode())
        aims.extend(Seqner(snh=serder.snh).qb64b)
        aims.extend(serder.said.encode())
        sims = bytearray() # attachment sub-sub-stream
        riger = signers2[0].sign(serder.raw, index=0)  # return siger
        sims.extend(riger.qb64b)
        # enclose and extend with quadlet counter, enclose defaults to V2
        aims.extend(Counter.enclose(qb64=sims, code=Codens.ControllerIdxSigs))
        # enclose and extend with quadlet counter, enclose defaults to V2
        emas.extend(Counter.enclose(qb64=aims, code=Codens.TransReceiptIdxSigGroups))

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
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1, **V2_CESR_KWA)

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
                        ndigs=[Diger(ser=signers2[3].verfer.qb64b).qb64],
                        sn=2, **V2_CESR_KWA)
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
                          sn=3, **V2_CESR_KWA)
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
                          sn=4, **V2_CESR_KWA)

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
                        ndigs=[Diger(ser=signers2[4].verfer.qb64b).qb64],
                        sn=5, **V2_CESR_KWA)
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
                          sn=6, **V2_CESR_KWA)
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
                        sn=7, **V2_CESR_KWA)

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
                          sn=8, **V2_CESR_KWA)

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
                        ndigs=[Diger(ser=signers2[5].verfer.qb64b).qb64],
                        sn=8, **V2_CESR_KWA)

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


def test_parser_v2_substream():
    """Test the support functionality for Parser stream processor CESR v2
    for substreamed message attachemments

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
    signers2 = Salter(raw=raw).signers(count=8, path='psr', temp=True)


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

        kevery = Kevery(db=valDB)

        parser = Parser(kvy=kevery, version=Vrsn_2_0)
        assert parser.genus == GenDex.KERI
        assert parser.version == Vrsn_2_0
        assert parser.local == False
        assert parser.framed == True
        assert parser.piped == False
        assert parser.ims == bytearray()
        assert parser.kvy == kevery
        assert parser.tvy is None
        assert parser.exc is None
        assert parser.rvy is None
        assert parser.vry is None


        # Event 0  Inception Transferable (nxt digest not empty)
        serder0 = incept(keys=[signers2[0].verfer.qb64],
                        ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64],
                        version=Vrsn_2_0,
                        kind=Kinds.cesr)
        assert serder0.pvrsn == Vrsn_2_0
        assert serder0.gvrsn == Vrsn_2_0

        # sign serialization indexed controller sigs group count quadlets
        siger0 = signers2[0].sign(serder0.raw, index=0)  # return siger
        msg0 = messagize(serder=serder0, sigers=[siger0], nested=True, gvrsn=Vrsn_2_0)

        # Event 1 Rotation Transferable
        serder1 = rotate(pre=serder0.pre,
                        keys=[signers2[1].verfer.qb64],
                        dig=serder0.said,
                        ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                        sn=1,
                        version=Vrsn_2_0,
                        kind=Kinds.cesr)
        # sign serialization
        siger1 = signers2[1].sign(serder1.raw, index=0)  # returns siger
        msg1 = messagize(serder=serder1, sigers=[siger1], framed=False, gvrsn=Vrsn_2_0)

        # now create message using messagize with msg0 and msg1 as nests
        attributes = dict(a=serder0.said, b=serder1.said)
        nonce = '0AB8WKheGX-o1b1SzLaxZr4u'
        dts = '2026-06-24T20:39:40.737875+00:00'  # helping.nowIso8601()
        serder2 = exchept(sender=serder0.pre,
                          receiver=serder0.pre,
                          nonce=nonce,
                          stamp=dts,
                          attributes = attributes,
                          kind=Kinds.cesr,
                          pvrsn=Vrsn_2_0)

        siger2 = signers2[0].sign(ser=serder2.raw, index=0)  # default indexed True
        msg2 = messagize(serder2, sigers=[siger2], nests=[msg0, msg1], nested=True)

        assert msg2 == (b'-BEX-FBP0OKERICAACAAXxipENigDsiL9CrHdU-yn5hOVQM5zKg6xktazQqYLUKp'
          b'i1Kq0AB8WKheGX-o1b1SzLaxZr4uDNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJI'
          b'WDiXp4HxDNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx1AAG2026-06-'
          b'24T20c39c40d737875p00c004AAA-IAA-IAY0J_aEFaYE2LTv8dItUgQzIHKRA9F'
          b'aHDrHtIHNs-m5DJKWXRN0J_bELd8a717hYxwewOwgmZfNRUaSmpBZpABZsOHduLd'
          b'1cg8-KAWAADKmJDaLkMGw6NUYyWAYFY4uBWItPntgZflpuIA5hk2WqqlGWj-JMpX'
          b'bxPYON9eCj47Wj0wqG1IraSpr1huW6kB-BBR-FA50OKERICAACAAXicpEFaYE2LT'
          b'v8dItUgQzIHKRA9FaHDrHtIHNs-m5DJKWXRNDNG2arBDtHK_JyHRAq-emRdC6UM-'
          b'yIpCAeJIWDiXp4HxMAAAMAAB-JALDNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJI'
          b'WDiXp4HxMAAB-JALEFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2MAAA'
          b'-JAA-JAA-JAA-KAWAADIuhb1P2QTiAdAsff8zRQi4z7DKqXyCWtQj8NllWrD9CQU'
          b'KpRB3NCpg_SX3LV2gAqlpbIkX0vDt61yhQmZfUYN-FBF0OKERICAACAAXrotELd8'
          b'a717hYxwewOwgmZfNRUaSmpBZpABZsOHduLd1cg8DNG2arBDtHK_JyHRAq-emRdC'
          b'6UM-yIpCAeJIWDiXp4HxMAABEFaYE2LTv8dItUgQzIHKRA9FaHDrHtIHNs-m5DJK'
          b'WXRNMAAB-JALDOwvH3i0ceL1GBqaLxecDIsk6NFDL-Qv6SFq5Gj6JMABMAAB-JAL'
          b'EFOcjb2T4uNP6C20sStcAzOyXDU27_2vWpTzAFbTarAcMAAA-JAA-JAA-JAA-JAA'
          b'-CAX-KAWAAB030oDC6rw-sdMygaNxzsoIFdgl0n02BbIkLEcT-Ot2d26rBW6TmIw'
          b'AeGFicXl1pOwJ8X4Zah4idvMuP3F688P')


        ims = bytearray(msg2)

        results = parser.parse(ims=ims, framed=False, processive=False)
        assert ims == bytearray(b'')  # emptied
        assert len(results) == 1
        result = results[0]

        assert result.serder.said == serder2.said
        assert result.nests[0].serder.said == serder0.said
        assert result.nests[1].serder.said == serder1.said

        # redo with differnt events
        # Event 0  Inception Transferable (nxt digest not empty)
        serder3 = incept(keys=[signers2[0].verfer.qb64],
                             ndigs=[Diger(ser=signers2[1].verfer.qb64b).qb64],
                            version=Vrsn_2_0,
                            kind=Kinds.json)

        # sign serialization indexed controller sigs group count quadlets
        siger3 = signers2[0].sign(serder3.raw, index=0)  # return siger
        msg3 = messagize(serder=serder3, sigers=[siger3], nested=True, gvrsn=Vrsn_2_0)

        # Event 1 Rotation Transferable
        serder4 = rotate(pre=serder3.pre,
                             keys=[signers2[1].verfer.qb64],
                            dig=serder3.said,
                            ndigs=[Diger(ser=signers2[2].verfer.qb64b).qb64],
                            sn=1,
                            version=Vrsn_2_0,
                            kind=Kinds.json)
        # sign serialization
        siger4 = signers2[1].sign(serder4.raw, index=0)  # returns siger
        msg4 = messagize(serder=serder4, sigers=[siger4], nested=True, gvrsn=Vrsn_2_0)

        # now create message using messagize with msg3 and msg4 as nests
        attributes = dict(a=serder3.said, b=serder4.said)
        nonce = '0AB8WKheGX-o1b1SzLaxZr4u'
        dts = '2026-06-24T20:39:40.737875+00:00'  # helping.nowIso8601()
        serder5 = exchept(sender=serder3.pre,
                              receiver=serder3.pre,
                              nonce=nonce,
                              stamp=dts,
                              attributes = attributes,
                              kind=Kinds.json,
                              pvrsn=Vrsn_2_0)

        siger5 = signers2[0].sign(ser=serder5.raw, index=0)  # default indexed True
        msg5 = messagize(serder5, sigers=[siger5], nests=[msg3, msg4], framed=False)

        ims = bytearray(msg5)

        results = parser.parse(ims=ims, framed=False, processive=False)
        assert ims == bytearray(b'')  # emptied
        assert len(results) == 1
        result = results[0]

        assert result.serder.said == serder5.said
        assert result.nests[0].serder.said == serder3.said
        assert result.nests[1].serder.said == serder4.said

        # now have two successful msgs with substeams in stream
        ims = bytearray(msg2)
        ims.extend(msg5)

        results = parser.parse(ims=ims, framed=True, processive=False)
        assert ims == bytearray(b'')  # emptied
        assert len(results) == 2

        result = results[0]
        assert result.serder.said == serder2.said
        assert result.nests[0].serder.said == serder0.said
        assert result.nests[1].serder.said == serder1.said

        result = results[1]
        assert result.serder.said == serder5.said
        assert result.nests[0].serder.said == serder3.said
        assert result.nests[1].serder.said == serder4.said

        """Done Test"""


def faultFixture():
    """Returns (signers, serder, msg) for a well formed v1 inception plus its
    attached controller signature. Shared setup for the fault sink tests below.

    Returns:
        signers (list[Signer]): transferable signers, [0] signs the inception
        serder (SerderKERI): the inception event
        msg (bytearray): serder.raw plus a ControllerIdxSigs group of one sig"""
    signers = Salter(raw=b"ABCDEFGH01234567").signers(count=8, path='psr', temp=True)
    serder = incept(keys=[signers[0].verfer.qb64],
                    ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **V1_KWA)
    msg = bytearray(serder.raw)
    msg.extend(Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0).qb64b)
    msg.extend(signers[0].sign(serder.raw, index=0).qb64b)
    return signers, serder, msg


def test_parser_fault_sink_default_off():
    """Test that the fault sink is opt-in, so an embedder that does not ask for
    one collects nothing and pays nothing"""
    parser = Parser()
    assert parser.faults is None  # off unless asked for

    faults = []
    parser = Parser(faults=faults)
    assert parser.faults is faults  # sink is held, not copied


def test_parser_fault_sink_silent_when_clean():
    """Test that a well formed stream produces no faults and still parses"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_1_0)

        faults = []
        parser.parse(ims=bytearray(msg), kvy=kvy, faults=faults)
        assert not faults  # nothing went wrong so nothing was collected
        assert serder.pre in kvy.kevers  # and the event was accepted

    """Done Test"""


def test_fault_kind():
    """Test that faultKind names the most specific KeriError in the cause chain.

    The parser rewraps as it unwinds so the class a handler catches is often
    less specific than the class that named the fault"""
    assert faultKind(ShortageError("need more")) == 'ShortageError'

    try:  # what groupParsator does to an extraction error as it unwinds
        try:
            raise ShortageError("need more")
        except ShortageError as ex:
            raise ExtractionError from ex
    except ExtractionError as ex:
        assert faultKind(ex) == 'ShortageError'  # not the bare wrapper

    try:  # what msgProcess does when it has no processor to dispatch to
        try:
            raise AttributeError("no kevery")
        except AttributeError as ex:
            raise ValidationError("no kevery to process") from ex
    except ValidationError as ex:
        assert faultKind(ex) == 'ValidationError'  # not the non-KeriError cause

    assert faultKind(RuntimeError("not ours")) == 'RuntimeError'

    """Done Test"""


def test_parser_fault_truncated_stream():
    """Test that a stream cut short surfaces as a flushed ShortageError"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_1_0)

        faults = []
        # cut into the attached signature so the body and its counter extract
        # but the signature itself runs short
        parser.parse(ims=bytearray(msg)[:-20], kvy=kvy, faults=faults)

        assert serder.pre not in kvy.kevers  # nothing was established
        assert len(faults) == 1
        fault = faults[0]
        assert isinstance(fault, Fault)
        assert fault.kind == 'ShortageError'  # ran short, so more bytes may help
        assert fault.disp == Disps.flush  # rest of stream discarded
        assert fault.offset == len(serder.raw) + 4  # body plus its sig counter
        assert fault.pre is None  # never got far enough to know whose msg it was
        assert fault.sn is None
        assert fault.said is None
        assert isinstance(fault.ex, ExtractionError)

    """Done Test"""


def test_parser_fault_cold_start():
    """Test that a desynced stream, one that starts on an attachment instead of
    a message, surfaces as a flushed ColdStartError and not as a shortage"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    # attachments with no message body in front of them, as a receiver would
    # see after resyncing mid stream
    orphan = bytearray(Counter(Codens.ControllerIdxSigs, count=1,
                               version=Vrsn_2_0).qb64b)
    orphan.extend(signers[0].sign(serder.raw, index=0).qb64b)

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_2_0)

        faults = []
        parser.parse(ims=bytearray(orphan), kvy=kvy, faults=faults)

        assert len(faults) == 1
        fault = faults[0]
        assert fault.kind == 'ColdStartError'  # desynced, more bytes will not help
        assert fault.disp == Disps.flush
        assert fault.offset == 0  # stream never made sense at all
        assert fault.pre is None

    """Done Test"""


def test_parser_fault_post_extraction():
    """Test that a msg which extracts but fails validation surfaces as a
    resumed fault carrying the identity of the msg that failed"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    # the inception with an empty signature group, so it extracts cleanly and
    # then fails validation for want of signatures
    unsigned = bytearray(serder.raw)
    unsigned.extend(Counter(Codens.ControllerIdxSigs, count=0,
                            version=Vrsn_1_0).qb64b)

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_1_0)

        faults = []
        parser.parse(ims=bytearray(unsigned), kvy=kvy, faults=faults)

        assert serder.pre not in kvy.kevers
        assert len(faults) == 1
        fault = faults[0]
        assert fault.kind == 'ValidationError'
        assert fault.disp == Disps.resume  # stream was not flushed
        assert fault.offset is None  # locus is the msg, not a byte position
        assert fault.pre == serder.pre  # extraction succeeded so identity is known
        assert fault.sn == 0
        assert fault.said == serder.said

    """Done Test"""


def test_parser_fault_discriminates_and_resumes():
    """Test that an out of order event is distinguishable from a stream that
    does not parse, and that the msgs after it still parse.

    This is the discrimination an embedder cannot make today. Both conditions
    establish less than the stream should, and .parse returns normally for
    both"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    # an interaction event for an identifier whose inception has not been seen
    ixn = interact(pre=serder.pre, dig=serder.said, sn=5, **V1_KWA)
    msgs = bytearray(ixn.raw)
    msgs.extend(Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0).qb64b)
    msgs.extend(signers[0].sign(ixn.raw, index=0).qb64b)
    msgs.extend(msg)  # the well formed inception follows it

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_1_0)

        faults = []
        parser.parse(ims=bytearray(msgs), kvy=kvy, faults=faults)

        assert len(faults) == 1
        fault = faults[0]
        assert fault.kind == 'OutOfOrderError'  # not merely 'ValidationError'
        assert fault.disp == Disps.resume
        assert fault.pre == ixn.pre
        assert fault.sn == 5
        assert fault.said == ixn.said
        assert isinstance(fault.ex, OutOfOrderError)

        # resumed, so the inception behind the bad event was still accepted
        assert serder.pre in kvy.kevers

    """Done Test"""


def test_parser_fault_sized_group():
    """Test that a fault inside a sized group is reported as such, since the
    group was already stripped from the stream and only its contents are lost"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    # generic group contents are attachments with no message body in front of
    # them, so extracting inside the group fails. All CESR so quadlet aligned
    inner = bytearray(Counter(Codens.ControllerIdxSigs, count=1,
                              version=Vrsn_1_0).qb64b)
    inner.extend(signers[0].sign(serder.raw, index=0).qb64b)
    assert len(inner) % 4 == 0

    msgs = bytearray(Counter(Codens.GenericGroup, count=len(inner) // 4,
                             version=Vrsn_1_0).qb64b)
    msgs.extend(inner)
    msgs.extend(msg)  # the well formed inception follows the bad group

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_1_0)

        faults = []
        parser.parse(ims=bytearray(msgs), kvy=kvy, faults=faults)

        assert len(faults) == 1
        fault = faults[0]
        assert fault.kind == 'SizedGroupError'
        assert fault.disp == Disps.group  # group lost, stream not flushed
        assert fault.offset == len(msgs) - len(msg)  # end of the failed group

        # only the group was lost, so the msg behind it was still accepted
        assert serder.pre in kvy.kevers

    """Done Test"""


def test_parser_fault_sink_on_parse_one():
    """Test that .parseOne reports faults the same way .parse does"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    unsigned = bytearray(serder.raw)
    unsigned.extend(Counter(Codens.ControllerIdxSigs, count=0,
                            version=Vrsn_1_0).qb64b)

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_1_0)

        faults = []
        parser.parseOne(ims=bytearray(unsigned), kvy=kvy, faults=faults)
        assert len(faults) == 1
        assert faults[0].kind == 'ValidationError'
        assert faults[0].disp == Disps.resume
        assert faults[0].pre == serder.pre
        assert faults[0].said == serder.said

        faults = []
        parser.parseOne(ims=bytearray(msg)[:-20], kvy=kvy, faults=faults)
        assert faults[0].kind == 'ShortageError'
        assert faults[0].disp == Disps.flush
        assert faults[0].offset == len(serder.raw) + 4
        # note: .onceParsator falls through into .msgProcess after a failed
        # extraction, where exts is unbound, so a spurious follow-on fault may
        # trail this one. Deliberately not asserted either way here, since that
        # is a parser bug this sink only makes visible

    """Done Test"""


def test_parser_fault_sink_never_raises():
    """Test that collecting a fault cannot itself break parsing, whatever the
    sink is handed"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_1_0)

        # a deque works as well as a list, since only .append is used
        faults = deque()
        parser.parse(ims=bytearray(msg)[:-20], kvy=kvy, faults=faults)
        assert len(faults) == 1
        assert faults[0].kind == 'ShortageError'

        # and a bounded one does not grow without limit on a long lived stream
        faults = deque(maxlen=1)
        parser.parse(ims=bytearray(msg)[:-20], kvy=kvy, faults=faults)
        parser.parse(ims=bytearray(msg)[:-20], kvy=kvy, faults=faults)
        assert len(faults) == 1

    """Done Test"""


def test_parser_fault_sink_on_live_stream():
    """Test that the always running .parsator reports faults, since a server
    parsing a live stream is the case an embedder most needs to diagnose"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    orphan = bytearray(Counter(Codens.ControllerIdxSigs, count=1,
                               version=Vrsn_2_0).qb64b)
    orphan.extend(signers[0].sign(serder.raw, index=0).qb64b)

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_2_0)

        ims = bytearray()
        faults = []
        parsator = parser.parsator(ims=ims, kvy=kvy, faults=faults)
        next(parsator)  # nothing in the stream yet
        assert not faults

        ims.extend(orphan)  # stream goes bad while the server is running
        next(parsator)

        assert len(faults) == 1
        assert faults[0].kind == 'ColdStartError'
        assert faults[0].disp == Disps.flush

    """Done Test"""


def test_parser_fault_unexpected_error():
    """Test that an error which is neither an extraction failure nor a post
    extraction validation failure still reaches the sink instead of vanishing.

    A substream that declares a CESR major version the parser does not support
    raises InvalidVersionError, which is a MaterialError, so it unwinds past
    every handler that names a cause and lands in the blanket arm"""
    logger.setLevel("ERROR")

    # generic group whose contents declare an unsupported genus version
    gvc = Counter(countB64=Counter.verToB64(major=3, minor=0),
                  code=Codens.KERIACDCGenusVersion, version=Vrsn_2_0)
    inner = bytearray(gvc.qb64b)
    assert len(inner) % 4 == 0

    msgs = bytearray(Counter(Codens.GenericGroup, count=len(inner) // 4,
                             version=Vrsn_2_0).qb64b)
    msgs.extend(inner)

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        parser = Parser(version=Vrsn_2_0)

        faults = []
        parser.parse(ims=bytearray(msgs), kvy=kvy, faults=faults)

        assert len(faults) == 1
        assert faults[0].kind == 'InvalidVersionError'
        assert faults[0].disp == Disps.resume

    """Done Test"""


def test_parser_fault_sink_instance_default():
    """Test that a sink given to the Parser is used by calls that do not
    provide one of their own, and that a per call sink overrides it"""
    logger.setLevel("ERROR")
    signers, serder, msg = faultFixture()

    with openDB(name="validator") as valDB:
        kvy = Kevery(db=valDB, lax=False, local=False)
        standing = []
        parser = Parser(version=Vrsn_1_0, faults=standing)

        parser.parse(ims=bytearray(msg)[:-20], kvy=kvy)
        assert len(standing) == 1
        assert standing[0].kind == 'ShortageError'

        oneoff = []
        parser.parse(ims=bytearray(msg)[:-20], kvy=kvy, faults=oneoff)
        assert len(oneoff) == 1  # per call sink got it
        assert len(standing) == 1  # and the standing sink did not

    """Done Test"""


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
    test_parser_v2_substream()
    test_parser_fault_sink_default_off()
    test_parser_fault_sink_silent_when_clean()
    test_fault_kind()
    test_parser_fault_truncated_stream()
    test_parser_fault_cold_start()
    test_parser_fault_post_extraction()
    test_parser_fault_discriminates_and_resumes()
    test_parser_fault_sized_group()
    test_parser_fault_sink_on_parse_one()
    test_parser_fault_sink_never_raises()
    test_parser_fault_sink_on_live_stream()
    test_parser_fault_unexpected_error()
    test_parser_fault_sink_instance_default()
