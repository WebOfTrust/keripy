import os

import pytest

from keri import help
from keri.app import keeping, habbing
from keri.core import parsing, eventing, coring
from keri.core.coring import CtrDex, Counter
from keri.core.coring import Signer, Nexter
from keri.core.eventing import Kever, Kevery
from keri.core.eventing import (incept, rotate, interact)
from keri.db import basing, dbing
from keri.db.basing import openDB
from keri.kering import (ValidationError)

logger = help.ogler.getLogger()


def test_kevery():
    """
    Test the support functionality for Kevery factory class
    Key Event Verifier Factory
    """
    logger.setLevel("ERROR")

    # Test sequence of events given set of secrets
    secrets = [
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
    ]

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:
        event_digs = []  # list of event digs in sequence

        # create event stream
        msgs = bytearray()
        #  create signers
        signers = [Signer(qb64=secret) for secret in secrets]  # faster
        assert [signer.qb64 for signer in signers] == secrets

        # Event 0  Inception Transferable (nxt digest not empty)
        serder = incept(keys=[signers[0].verfer.qb64],
                        nxt=Nexter(keys=[signers[1].verfer.qb64]).qb64)
        event_digs.append(serder.dig)
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

        assert msgs == bytearray(b'{"v":"KERI10JSON0000ed_","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOo'
                                 b'eKtWTOunRA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5t'
                                 b'zHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIy'
                                 b'a3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAmagesCSY8QhYY'
                                 b'HCJXEWpsGD62qoLt2uyT0_Mq5lZPR88JyS5UrwFKFdcjPqyKc_SKaKDJhkGWCk07'
                                 b'k_kVkjyCA')

        # Event 1 Rotation Transferable
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[1].verfer.qb64],
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[2].verfer.qb64]).qb64,
                        sn=1)
        event_digs.append(serder.dig)
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
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[3].verfer.qb64]).qb64,
                        sn=2)
        event_digs.append(serder.dig)
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
                          dig=kever.serder.diger.qb64,
                          sn=3)
        event_digs.append(serder.dig)
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
                          dig=kever.serder.diger.qb64,
                          sn=4)
        event_digs.append(serder.dig)
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
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[4].verfer.qb64]).qb64,
                        sn=5)
        event_digs.append(serder.dig)
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
                          dig=kever.serder.diger.qb64,
                          sn=6)
        event_digs.append(serder.dig)
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
                        dig=kever.serder.diger.qb64,
                        nxt="",
                        sn=7)
        event_digs.append(serder.dig)
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
                          dig=kever.serder.diger.qb64,
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

        # Event 8 Rotation
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[signers[4].verfer.qb64],
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=[signers[5].verfer.qb64]).qb64,
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

        assert len(msgs) == 3171

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
    with basing.openDB(name="controller") as bobDB, keeping.openKS(name="controller") as bobKS:
        wits = [
            "BqMUu4hpUYY4FKd4LtsvpMN6claZKF2AUmXIgXiAI9ZQ",
            "BrCfvh5pSgaDJP9LzZwLYcVkygwqftkh0HJ4mTocHXec",
            "BjMgEv0cO_Jd7gIVVacDw_F234Y6oUw-DbfylPSDmvaA",
            "BD-9mx3Rt96Udd91oLr0_UQJ9XXi-122TGifFffTO5q8",
            "B29WvOreixuE3hFmCpuHUMz4VsujpvA1JrDM3uc3ACAA",
            "B0zM6ejHbOgObBwrdTkBqfq4eXFLXl_Zrf-RS7q9xbj4",
            "BY2rPvRFl7g6pfmy-5KsJDSI46cA5mNvSw8FteNVXSCY",
            "B7ejskZg8S5rVMvTb_8qB240UxP6NKk_HRVKiCK_FwSc",
            "BnfnWbP3CTkWapC7rQxSkpioxkb-nbmhs-JoHbiwU5q4",
            "BA6_tnL-DK0s7bYdVFfm_AufLsimGGUMK6V3QXNOKSu0",
        ]

        hab = habbing.Habitat(name="controller", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                              wits=[wits[0], wits[1]], temp=True)

        wit0 = hab.kvy.fetchWitnessState(hab.pre, 0)
        assert [w.qb64 for w in wit0] == [wits[0], wits[1]]

        ixn0 = hab.interact()
        assert ixn0 == (
            b'{"v":"KERI10JSON000098_","i":"E1LbpWWhVBqV-9zIw5m8mJS7H9GQk9kPOUXPzaxCr3K4","s":"1","t":"ixn",'
            b'"p":"E62XcaRtiuo-BV8FH3IYwKdFv1RQaN6_vmqyQbB-6pAc",'
            b'"a":[]}-AABAATVbzN1wojYaWjOk-NtzzRAqb6R6jxM2ZSx3ngjlh7OQugZ96eeR_dToZvNEUXgWNzMr78SqNh8enNLFqrHsXAg')
        wit1 = hab.kvy.fetchWitnessState(hab.pre, 1)
        assert [w.qb64 for w in wit1] == [wits[0], wits[1]]

        rot1 = hab.rotate()
        assert rot1 == (
            b'{"v":"KERI10JSON000122_","i":"E1LbpWWhVBqV-9zIw5m8mJS7H9GQk9kPOUXPzaxCr3K4","s":"2","t":"rot",'
            b'"p":"EWcTuZ-tqCAjJna6Mv2HyDhQgcvcvrKwtkYLpUQmI0AI","kt":"1",'
            b'"k":["DODc-zWRbn5SLtdAzxLFpGDqf6zXaJlAX85rfiIRn1-M"],'
            b'"n":"E7giSjZhH8qC_oXAqUoA8JoOlal15MsEtTr30JTMwgi0","bt":"2","br":[],"ba":[],'
            b'"a":[]}-AABAAUpqRgrsdJ6vh9Be5J89I_K82W0MQxyVx5p4HSu9rCihGMoaGT9c-RZzAkHDTu7XNRhvewlApMcbxk6o3MoWkAA')
        wit2 = hab.kvy.fetchWitnessState(hab.pre, 2)
        assert [w.qb64 for w in wit2] == [wits[0], wits[1]]

        rot2 = hab.rotate(cuts=[wits[0]], adds=wits[7:])
        assert rot2 == (
            b'{"v":"KERI10JSON0001dc_","i":"E1LbpWWhVBqV-9zIw5m8mJS7H9GQk9kPOUXPzaxCr3K4","s":"3","t":"rot",'
            b'"p":"EgtUMcQQH5Sdjeb4tL3Zg5kr2qvozUtRu3nIwHUKqjYY","kt":"1",'
            b'"k":["DqWc3AKqVH6kvMH6n0mWb472P1Ckl-JzWynqS2H0N6LQ"],'
            b'"n":"EhAly7aOUUvArcUdJgqag1K4nf7mODsgDnZhJGQnOBzE","bt":"3",'
            b'"br":["BqMUu4hpUYY4FKd4LtsvpMN6claZKF2AUmXIgXiAI9ZQ"],'
            b'"ba":["B7ejskZg8S5rVMvTb_8qB240UxP6NKk_HRVKiCK_FwSc","BnfnWbP3CTkWapC7rQxSkpioxkb-nbmhs-JoHbiwU5q4",'
            b'"BA6_tnL-DK0s7bYdVFfm_AufLsimGGUMK6V3QXNOKSu0"],'
            b'"a":[]}-AABAAaiYKw3F5UVNeHSngVa8iX76XsIw87hIt0bzVewxPNSDhMUfu6yHUil7z5rHMSVEDPA6cajaOaUBE4xrr4cHZAg')
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
    # Bob is the controller
    # Wes, Wil and Wan are his witnesses
    # Bam is verifying the key events with receipts from Bob
    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         basing.openDB(name="wan") as wanDB, keeping.openKS(name="wan") as wanKS, \
         basing.openDB(name="wil") as wilDB, keeping.openKS(name="wil") as wilKS, \
         basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
         basing.openDB(name="bam") as bamDB:

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1, transferable=False, temp=True)

        assert wesHab.pre == "BK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c"

        # setup Wan's habitat nontrans
        wanHab = habbing.Habitat(name='wan', ks=wanKS, db=wanDB,
                                 isith=1, icount=1, transferable=False, temp=True)

        assert wanHab.pre == "BBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq148"

        # setup Wil's habitat nontrans
        wilHab = habbing.Habitat(name='wil', ks=wilKS, db=wilDB,
                                 isith=1, icount=1, transferable=False, temp=True)

        assert wilHab.pre == "BRetJdWSxemd-ej8OLpEFfYuyv1VZECKGMuGjB-M05BA"

        # setup Bob's transferable habitat with wil, wes and wan as witnesses
        awits = [wesHab, wilHab, wanHab]
        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[wesHab.pre, wilHab.pre, wanHab.pre], toad=2, temp=True)
        assert bobHab.pre == "ElW9qSk_RNt9bhRVtw315BpLMoHuA5gLs3NuYZUQpF1U"
        
        bamKvy = eventing.Kevery(db=bamDB, lax=False, local=False)

        # Pass incept to witnesses, receipted event to bam
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=bamKvy)
        assert bobHab.pre not in bamKvy.kevers

        for witHab in awits:
            kvy = eventing.Kevery(db=witHab.db, lax=False, local=False)
            parsing.Parser().parse(ims=bytearray(bobIcp), kvy=kvy)
            assert bobHab.pre in witHab.kevers
            iserder = coring.Serder(raw=bytearray(bobIcp))
            msg = witHab.receipt(serder=iserder)
            parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        bamKvy.processEscrows()
        assert bobHab.pre in bamKvy.kevers

        # Rotate, pass to witnesses, send receipts from Wes and Wan to Bam
        rot0 = bobHab.rotate(toad=2)
        parsing.Parser().parse(ims=bytearray(rot0), kvy=bamKvy)

        for witHab in [wesHab, wanHab]:
            kvy = eventing.Kevery(db=witHab.db, lax=False, local=False)
            parsing.Parser().parse(ims=bytearray(rot0), kvy=kvy)
            iserder = coring.Serder(raw=bytearray(rot0))
            msg = witHab.receipt(serder=iserder)
            parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        bamKvy.processEscrows()
        assert bamKvy.kevers[bobHab.pre].sn == 1

        # Validate that bam has 2 receipts in DB for event 1
        ser = coring.Serder(raw=rot0)
        dgkey = dbing.dgKey(ser.preb, ser.digb)
        wigs = bamDB.getWigs(dgkey)
        assert len(wigs) == 2


        # Rotate out Wil, pass to witnesses, receipted event to bam.
        rot1 = bobHab.rotate(cuts=[wilHab.pre], toad=2)
        parsing.Parser().parse(ims=bytearray(rot1), kvy=bamKvy)

        for witHab in [wesHab, wanHab]:
            kvy = eventing.Kevery(db=witHab.db, lax=False, local=False)
            parsing.Parser().parse(ims=bytearray(rot1), kvy=kvy)
            iserder = coring.Serder(raw=bytearray(rot1))
            msg = witHab.receipt(serder=iserder)
            parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        bamKvy.processEscrows()
        assert bamKvy.kevers[bobHab.pre].sn == 2
        assert bamKvy.kevers[bobHab.pre].wits == [wesHab.pre, wanHab.pre]

        # Pass receipts from Wil for event 1 to Bam
        kvy = eventing.Kevery(db=wilHab.db, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(rot0), kvy=kvy)
        iserder = coring.Serder(raw=bytearray(rot0))
        msg = wilHab.receipt(serder=iserder)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        # Validate that bam has 3 receipts in DB for event 1
        wigs = bamDB.getWigs(dgkey)
        assert len(wigs) == 3


        """ Done Test """
