import os

import pytest

from keri import help
from keri.app import habbing
from keri.core import parsing, eventing, coring, serdering
from keri.core.coring import CtrDex, Counter
from keri.core.coring import Salter
from keri.core.eventing import Kever, Kevery
from keri.core.eventing import (incept, rotate, interact)
from keri.db import dbing
from keri.db.basing import openDB
from keri.kering import (ValidationError)

logger = help.ogler.getLogger()


def test_kevery():
    """
    Test the support functionality for Kevery factory class
    Key Event Verifier Factory
    """
    logger.setLevel("ERROR")

    #  create signers
    raw = b"ABCDEFGH01234567"
    signers = Salter(raw=raw).signers(count=8, path='kev', temp=True)

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:
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
        kever = Kever(serder=serder, sigers=[siger], db=conlgr)
        # extend key event stream
        msgs.extend(serder.raw)
        msgs.extend(counter.qb64b)
        msgs.extend(siger.qb64b)

        assert msgs == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"ECwI3rbyMMCCBrjBcZW-qIh4'
                        b'SFeY1ri6fl6nFNZ6_LPn","i":"DEzolW_U9CTatBFey9LL9e4_FOekoAJdTbReE'
                        b'stNEl-D","s":"0","kt":"1","k":["DEzolW_U9CTatBFey9LL9e4_FOekoAJd'
                        b'TbReEstNEl-D"],"nt":"1","n":["EL0nWR23_LnKW6OAXJauX2oz6N2V_QZfWe'
                        b'T4tsK-y3jZ"],"bt":"0","b":[],"c":[],"a":[]}-AABAAB7Ro77feCA8A0B6'
                        b'32ThEzVKGHwUrEx-TGyV8VdXKZvxPivaWqR__Exa7n02sjJkNlrQcOqs7cXsJ6ID'
                        b'opxkbEC')

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

        # Event 8 Interaction
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

        # Event 8 Rotation override interaction
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

        kevery = Kevery(db=vallgr)

        # test for incomplete event in stream  (new process just hangs waiting for more bytes)
        # kevery.process(ims=kes[:20])
        # assert pre not in kevery.kevers  # shortage so gives up

        parsing.Parser().parse(ims=msgs, kvy=kevery)
        # kevery.process(ims=msgs)

        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == kever.sn
        assert vkever.verfers[0].qb64 == kever.verfers[0].qb64
        assert vkever.verfers[0].qb64 == signers[4].verfer.qb64

        db_digs = [bytes(val).decode("utf-8") for val in kevery.db.getKelIter(pre)]
        assert db_digs == event_digs

    assert not os.path.exists(kevery.db.path)
    assert not os.path.exists(kever.db.path)

    """ Done Test """


def test_witness_state():
    """
    """

    # with basing.openDB(name="controller") as bobDB, keeping.openKS(name="controller") as bobKS:
    with habbing.openHby(name="controller", base="test") as hby:

        wits = [
            "BAMUu4hpUYY4FKd4LtsvpMN6claZKF2AUmXIgXiAI9ZQ",
            "BBCfvh5pSgaDJP9LzZwLYcVkygwqftkh0HJ4mTocHXec",
            "BCMgEv0cO_Jd7gIVVacDw_F234Y6oUw-DbfylPSDmvaA",
            "BD-9mx3Rt96Udd91oLr0_UQJ9XXi-122TGifFffTO5q8",
            "BE9WvOreixuE3hFmCpuHUMz4VsujpvA1JrDM3uc3ACAA",
            "BFzM6ejHbOgObBwrdTkBqfq4eXFLXl_Zrf-RS7q9xbj4",
            "BG2rPvRFl7g6pfmy-5KsJDSI46cA5mNvSw8FteNVXSCY",
            "BHejskZg8S5rVMvTb_8qB240UxP6NKk_HRVKiCK_FwSc",
            "BIfnWbP3CTkWapC7rQxSkpioxkb-nbmhs-JoHbiwU5q4",
            "BJ6_tnL-DK0s7bYdVFfm_AufLsimGGUMK6V3QXNOKSu0",
        ]

        hab = hby.makeHab(name="controller", isith='1', icount=1, transferable=True,
                              wits=[wits[0], wits[1]])

        wit0 = hab.kvy.fetchWitnessState(hab.pre, 0)
        assert [w.qb64 for w in wit0] == [wits[0], wits[1]]

        ixn0 = hab.interact()
        assert ixn0 == (b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EMrHSIByF9uIw9rM9rdSWxLQ'
                b'IQiKloH-S5T8UO2Cq3xh","i":"EItocvw9Us8NGO5I3qff6dCCSsQzRSKMDzFUU'
                b'BXEYLAH","s":"1","p":"EItocvw9Us8NGO5I3qff6dCCSsQzRSKMDzFUUBXEYL'
                b'AH","a":[]}-AABAADk6eCpYOReWEfOboS-2cXiTVOdnk4kuKue3-MW507lt3O00'
                b'mOPxN44hr3v5rUr8AskyPEZmQ9ytnGUcgDED8sH')
        wit1 = hab.kvy.fetchWitnessState(hab.pre, 1)
        assert [w.qb64 for w in wit1] == [wits[0], wits[1]]

        rot1 = hab.rotate()
        assert rot1 == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EF3IIBRGoGr5Mq35UBuhmfiA'
                b'SkBAOc-sM5f8BUQisi6-","i":"EItocvw9Us8NGO5I3qff6dCCSsQzRSKMDzFUU'
                b'BXEYLAH","s":"2","p":"EMrHSIByF9uIw9rM9rdSWxLQIQiKloH-S5T8UO2Cq3'
                b'xh","kt":"1","k":["DDg3Ps1kW5-Ui7XQM8SxaRg6n-s12iZQF_Oa34iEZ9fj"'
                b'],"nt":"1","n":["ED23AK25MWXy-ZcUp3zK2k2armZczuiq6NJYvEH1sKK9"],'
                b'"bt":"2","br":[],"ba":[],"a":[]}-AABAACg2eJgQS5UHx25TpW14zgUlgXR'
                b'e-dqB7PkDd_4QKtb_CSLYqCyE-lGrEmMInDHRfbTLMzBz0DoOk2XPvhgC3QB')
        wit2 = hab.kvy.fetchWitnessState(hab.pre, 2)
        assert [w.qb64 for w in wit2] == [wits[0], wits[1]]

        rot2 = hab.rotate(cuts=[wits[0]], adds=wits[7:])
        assert rot2 == (b'{"v":"KERI10JSON00021a_","t":"rot","d":"EEmrPqJNzOC2DvZx--TCbB5o'
                b'pQ0Ewp7yXrzqAesXwwQ4","i":"EItocvw9Us8NGO5I3qff6dCCSsQzRSKMDzFUU'
                b'BXEYLAH","s":"3","p":"EF3IIBRGoGr5Mq35UBuhmfiASkBAOc-sM5f8BUQisi'
                b'6-","kt":"1","k":["DKlnNwCqlR-pLzB-p9Jlm-O9j9QpJfic1sp6kth9Dei0"'
                b'],"nt":"1","n":["EFW5n90Qcff1hCQ2yHqtWx2yRAah6xaGe0DzU_KDtH5D"],'
                b'"bt":"3","br":["BAMUu4hpUYY4FKd4LtsvpMN6claZKF2AUmXIgXiAI9ZQ"],"'
                b'ba":["BHejskZg8S5rVMvTb_8qB240UxP6NKk_HRVKiCK_FwSc","BIfnWbP3CTk'
                b'WapC7rQxSkpioxkb-nbmhs-JoHbiwU5q4","BJ6_tnL-DK0s7bYdVFfm_AufLsim'
                b'GGUMK6V3QXNOKSu0"],"a":[]}-AABAAAh7AIPmoZlq0cj6l07i82vkzj4k9f2MK'
                b'Ej9GZP1U9l9cCZhmUF6tg5csR1A5BUZ9ARu4tykFpYEBd13idanK8J')
        wit3 = hab.kvy.fetchWitnessState(hab.pre, 3)
        assert [w.qb64 for w in wit3] == [wits[1], wits[7], wits[8], wits[9]]

        for _ in range(5):
            hab.interact()
        assert hab.kever.sn == 8

        hab.rotate(cuts=[wits[8], wits[9]], adds=wits[2:5])
        assert hab.kever.sn == 9

        wit4 = hab.kvy.fetchWitnessState(hab.pre, 4)
        assert [w.qb64 for w in wit4] == [wits[1], wits[7], wits[8], wits[9]]
        wit4 = hab.kvy.fetchWitnessState(hab.pre, 5)
        assert [w.qb64 for w in wit4] == [wits[1], wits[7], wits[8], wits[9]]
        wit4 = hab.kvy.fetchWitnessState(hab.pre, 6)
        assert [w.qb64 for w in wit4] == [wits[1], wits[7], wits[8], wits[9]]
        wit4 = hab.kvy.fetchWitnessState(hab.pre, 7)
        assert [w.qb64 for w in wit4] == [wits[1], wits[7], wits[8], wits[9]]
        wit4 = hab.kvy.fetchWitnessState(hab.pre, 8)
        assert [w.qb64 for w in wit4] == [wits[1], wits[7], wits[8], wits[9]]

        wit5 = hab.kvy.fetchWitnessState(hab.pre, 9)
        assert [w.qb64 for w in wit5] == [wits[1], wits[7], wits[2], wits[3], wits[4]]

        # Verify history is still valid
        wit0 = hab.kvy.fetchWitnessState(hab.pre, 0)
        assert [w.qb64 for w in wit0] == [wits[0], wits[1]]
        wit1 = hab.kvy.fetchWitnessState(hab.pre, 1)
        assert [w.qb64 for w in wit1] == [wits[0], wits[1]]


def test_stale_event_receipts():
    """
    Bob is the controller
    Wes, Wil and Wan are his witnesses
    Bam is verifying the key events with receipts from Bob
    """
    # openHby default temp=True
    with (habbing.openHby(name="bob", base="test") as bobHby,
            habbing.openHby(name="bam", base="test") as bamHby,
            habbing.openHby(name="wes", base="test") as wesHby,
            habbing.openHby(name="wan", base="test") as wanHby,
            habbing.openHby(name="wil", base="test") as wilHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False,)
        assert wesHab.pre == 'BCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X'

        # setup Wan's habitat nontrans
        wanHab = wanHby.makeHab(name="wan", isith='1', icount=1, transferable=False,)
        assert wanHab.pre == 'BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP'

        # setup Wil's habitat nontrans
        wilHab = wilHby.makeHab(name="wil", isith='1', icount=1, transferable=False,)
        assert wilHab.pre == 'BEXrSXVksXpnfno_Di6RBX2Lsr9VWRAihjLhowfjNOQQ'

        # setup Bob's transferable habitat with wil, wes and wan as witnesses
        awits = [wesHab, wilHab, wanHab]
        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True,
                                wits=[wesHab.pre, wilHab.pre, wanHab.pre], toad=2,)
        assert bobHab.pre == 'EEM3_Vvu1R__sWolUiPQ8Mk97GQ1xsGbC9kqEfsFL1aO'

        bamKvy = eventing.Kevery(db=bamHby.db, lax=False, local=False)

        # Pass incept to witnesses, receipted event to bam
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=bamKvy, local=True)
        assert bobHab.pre not in bamKvy.kevers

        for witHab in awits:
            kvy = eventing.Kevery(db=witHab.db, lax=False, local=False)
            parsing.Parser().parse(ims=bytearray(bobIcp), kvy=kvy, local=True)
            assert bobHab.pre in witHab.kevers
            iserder = serdering.SerderKERI(raw=bytearray(bobIcp))
            msg = witHab.receipt(serder=iserder)
            parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, local=True)

        bamKvy.processEscrows()
        assert bobHab.pre in bamKvy.kevers

        # Rotate, pass to witnesses, send receipts from Wes and Wan to Bam
        rot0 = bobHab.rotate(toad=2)
        parsing.Parser().parse(ims=bytearray(rot0), kvy=bamKvy, local=True)

        for witHab in [wesHab, wanHab]:
            kvy = eventing.Kevery(db=witHab.db, lax=False, local=False)
            parsing.Parser().parse(ims=bytearray(rot0), kvy=kvy, local=True)
            iserder = serdering.SerderKERI(raw=bytearray(rot0))
            msg = witHab.receipt(serder=iserder)
            parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, local=True)

        bamKvy.processEscrows()
        assert bamKvy.kevers[bobHab.pre].sn == 1

        # Validate that bam has 2 receipts in DB for event 1
        ser = serdering.SerderKERI(raw=rot0)
        dgkey = dbing.dgKey(ser.preb, ser.saidb)
        wigs = bamHby.db.getWigs(dgkey)
        assert len(wigs) == 2

        # Rotate out Wil, pass to witnesses, receipted event to bam.
        rot1 = bobHab.rotate(cuts=[wilHab.pre], toad=2)
        parsing.Parser().parse(ims=bytearray(rot1), kvy=bamKvy, local=True)

        for witHab in [wesHab, wanHab]:
            kvy = eventing.Kevery(db=witHab.db)
            parsing.Parser().parse(ims=bytearray(rot1), kvy=kvy, local=True)
            iserder = serdering.SerderKERI(raw=bytearray(rot1))
            msg = witHab.receipt(serder=iserder)
            parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, local=True)

        bamKvy.processEscrows()
        assert bamKvy.kevers[bobHab.pre].sn == 2
        assert bamKvy.kevers[bobHab.pre].wits == [wesHab.pre, wanHab.pre]

        # Pass receipts from Wil for event 1 to Bam
        kvy = eventing.Kevery(db=wilHab.db)
        parsing.Parser().parse(ims=bytearray(rot0), kvy=kvy, local=True)
        iserder = serdering.SerderKERI(raw=bytearray(rot0))
        msg = wilHab.receipt(serder=iserder)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, local=True)

        # Validate that bam has 3 receipts in DB for event 1
        wigs = bamHby.db.getWigs(dgkey)
        assert len(wigs) == 3

        """ Done Test """


if __name__ == "__main__":
    test_kevery()
