# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os
import datetime

import pytest

from keri import help
from keri.help import helping
from keri.db import dbing, basing
from keri.app import habbing, keeping, directing
from keri.core import coring, eventing, parsing

logger = help.ogler.getLogger()


def test_indexed_witness_replay():
    """
    Test event validation logic with witnesses

    cam is controller
    van is validator
    wes is a witness
    wok is a witness
    wam is a witness

    """
    salt = coring.Salter(raw=b'abcdef0123456789').qb64

    with basing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
            basing.openDB(name="van") as vanDB, keeping.openKS(name="van") as vanKS, \
            basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
            basing.openDB(name="wok") as wokDB, keeping.openKS(name="wok") as wokKS, \
            basing.openDB(name="wam") as wamDB, keeping.openKS(name="wam") as wamKS, \
            basing.openDB(name="wil") as wilDB, keeping.openKS(name="wil") as wilKS:

        # witnesses first so can setup inception event for cam
        wsith = 1
        # setup Wes's habitat nontrans
        # Wes's receipts will be rcts with a receipt couple attached

        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wesHab.ks == wesKS
        assert wesHab.db == wesDB
        assert not wesHab.kever.prefixer.transferable
        # create non-local kevery for Wes to process nonlocal msgs
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)

        # setup Wok's habitat nontrans
        # Wok's receipts will be rcts with a receipt couple attached
        wokHab = habbing.Habitat(name='wok', ks=wokKS, db=wokDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wokHab.ks == wokKS
        assert wokHab.db == wokDB
        assert not wokHab.kever.prefixer.transferable
        # create non-local kevery for Wok to process nonlocal msgs
        wokKvy = eventing.Kevery(db=wokHab.db, lax=False, local=False)

        # setup Wam's habitat nontrans
        # Wams's receipts will be rcts with a receipt couple attached
        wamHab = habbing.Habitat(name='wam', ks=wamKS, db=wamDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wamHab.ks == wamKS
        assert wamHab.db == wamDB
        assert not wamHab.kever.prefixer.transferable
        # create non-local kevery for Wam to process nonlocal msgs
        wamKvy = eventing.Kevery(db=wamHab.db, lax=False, local=False)

        # setup Wil's habitat nontrans
        # Wil's receipts will be rcts with a receipt couple attached
        wilHab = habbing.Habitat(name='wil', ks=wilKS, db=wilDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wilHab.ks == wilKS
        assert wilHab.db == wilDB
        assert not wilHab.kever.prefixer.transferable
        # create non-local kevery for Wam to process nonlocal msgs
        wilKvy = eventing.Kevery(db=wilHab.db, lax=False, local=False)

        # setup Cam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre, wamHab.pre]
        csith = 2  # hex str of threshold int
        camHab = habbing.Habitat(name='cam', ks=camKS, db=camDB,
                                 isith=csith, icount=3,
                                 toad=2, wits=wits,
                                 salt=salt, temp=True)  # stem is .name
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable
        assert len(camHab.iserder.werfers) == len(wits)
        for werfer in camHab.iserder.werfers:
            assert werfer.qb64 in wits
        assert camHab.kever.wits == wits
        assert camHab.kever.toad == 2
        assert camHab.kever.sn == 0

        # create non-local kevery for Cam to process onlocal msgs
        camKvy = eventing.Kevery(db=camHab.db, lax=False, local=False)

        # setup Van's habitat trans multisig
        vsith = 2  # two of three signing threshold
        vanHab = habbing.Habitat(name='van', ks=vanKS, db=vanDB,
                                 isith=vsith, icount=3,
                                 salt=salt, temp=True)  # stem is .name
        assert vanHab.ks == vanKS
        assert vanHab.db == vanDB
        assert vanHab.kever.prefixer.transferable
        # create non-local kevery for Van to process nonlocal msgs
        vanKvy = eventing.Kevery(db=vanHab.db, lax=False, local=False)

        # make list so easier to batch
        camWitKvys = [wesKvy, wokKvy, wamKvy]
        camWitHabs = [wesHab, wokHab, wamHab]

        # Create Cam inception and send to each of Cam's witnesses
        camIcpMsg = camHab.makeOwnInception()
        rctMsgs = []  # list of receipts from each witness
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIcpMsg))  # send copy of cam icp msg to witness
            assert kvy.kevers[camHab.pre].sn == 0  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 617
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # process rct msgs from all witnesses
            parsing.Parser().parse(ims=bytearray(msg), kvy=camKvy)
            # camKvy.process(ims=bytearray(msg))  # make copy
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # get from Cam database copies of witness receipts received by Cam
        # and send to witnesses so all witnesses have full set of receipts
        # from all other witnesses
        # reply one event or receipt one event with all witness attachments
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.said)
        wigs = camHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigers = [coring.Siger(qb64b=bytes(wig)) for wig in wigs]
        rserder = eventing.receipt(pre=camHab.pre,
                                   sn=camHab.kever.sn,
                                   said=camHab.kever.serder.said)
        camIcpWitRctMsg = eventing.messagize(serder=rserder, wigers=wigers)
        assert len(camIcpWitRctMsg) == 413
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            parsing.Parser().parse(ims=bytearray(camIcpWitRctMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIcpWitRctMsg))  # send copy of witness rcts
            assert len(kvy.db.getWigs(dgkey)) == 3  # fully witnessed
            assert len(kvy.cues) == 0  # no cues

        # send Cam icp and witness rcts to Van
        parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=vanKvy)
        # should escrow since not witnesses
        assert camHab.pre not in vanKvy.kevers
        # process receipts
        parsing.Parser().parse(ims=bytearray(camIcpWitRctMsg), kvy=vanKvy)
        vanKvy.processEscrows()
        assert camHab.pre in vanKvy.kevers  # now accepted
        vcKvr = vanKvy.kevers[camHab.pre]
        assert vcKvr.sn == 0
        assert vcKvr.wits == wits

        # Create Cam ixn and send to each of Cam's witnesses
        camIxnMsg = camHab.interact()
        rctMsgs = []  # list of receipts from each witness
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            parsing.Parser().parse(ims=bytearray(camIxnMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIxnMsg))  # send copy of cam icp msg to witness
            assert kvy.kevers[camHab.pre].sn == 1  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 281
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # process rct msgs from all witnesses
            parsing.Parser().parse(ims=bytearray(msg), kvy=camKvy)
            # camKvy.process(ims=bytearray(msg))  # make copy
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # get from Cam database copies of witness receipts received by Cam
        # and send to witnesses so all witnesses have full set of receipts
        # from all other witnesses
        # reply one event or receipt one event with all witness attachments
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.said)
        wigs = camHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigers = [coring.Siger(qb64b=bytes(wig)) for wig in wigs]
        rserder = eventing.receipt(pre=camHab.pre,
                                   sn=camHab.kever.sn,
                                   said=camHab.kever.serder.said)
        camIxnWitRctMsg = eventing.messagize(serder=rserder, wigers=wigers)
        assert len(camIxnWitRctMsg) == 413
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            parsing.Parser().parse(ims=bytearray(camIxnWitRctMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIxnWitRctMsg))  # send copy of witness rcts
            assert len(kvy.db.getWigs(dgkey)) == 3  # fully witnessed
            assert len(kvy.cues) == 0  # no cues

        # send Cam ixn's witness rcts to Van first then send Cam ixn
        parsing.Parser().parse(ims=bytearray(camIxnWitRctMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camIxnWitRctMsg))
        vanKvy.processEscrows()
        assert vcKvr.sn == 0
        parsing.Parser().parse(ims=bytearray(camIxnMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camIxnMsg))  # should escrow since not witnesses
        assert vcKvr.sn == 0
        vanKvy.processEscrows()
        assert vcKvr.sn == 1

        # Cam replace Wok with Wil as a witness.
        # Cam update Wil all event witnessed events for Cam by replay
        # Cam update itself with Wil receipts including Wils inception
        camReplayMsg = camHab.replay()
        assert len(camReplayMsg) == 1933
        parsing.Parser().parse(ims=bytearray(camReplayMsg), kvy=wilKvy)
        # wilKvy.process(ims=bytearray(camReplayMsg))
        assert camHab.pre in wilKvy.kevers
        assert wilKvy.kevers[camHab.pre].sn == 1  # asscepted both events
        assert len(wilKvy.cues) == 2
        wilRctMsg = wilHab.processCues(wilKvy.cues)  # process cue returns rct msg
        assert len(wilKvy.cues) == 0
        parsing.Parser().parse(ims=bytearray(wilRctMsg), kvy=camKvy)
        # camKvy.process(ims=bytearray(wilRctMsg))  # make copy
        assert wilHab.pre in camKvy.kevers

        # Cam rotation with witness rotation
        camRotMsg = camHab.rotate(toad=2, cuts=[wokHab.pre], adds=[wilHab.pre])
        assert camHab.kever.wits == [wesHab.pre, wamHab.pre, wilHab.pre]
        assert camHab.kever.toad == 2
        assert camHab.kever.sn == 2

        # update lists of witness kvys and habs
        camWitKvys = [wesKvy, wamKvy, wilKvy]
        camWitHabs = [wesHab, wamHab, wilHab]

        rctMsgs = []  # list of receipt msgs from each witness
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            parsing.Parser().parse(ims=bytearray(camRotMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camRotMsg))  # send copy of cam msg to witness
            assert kvy.kevers[camHab.pre].sn == 2  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 281
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # process rct msgs from all witnesses
            parsing.Parser().parse(ims=bytearray(msg), kvy=camKvy)
            # camKvy.process(ims=bytearray(msg))  # make copy
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # get from Cam database copies of witness receipts received by Cam
        # and send to witnesses so all witnesses have full set of receipts
        # from all other witnesses
        # reply one event or receipt one event with all witness attachments
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.said)
        wigs = camHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigers = [coring.Siger(qb64b=bytes(wig)) for wig in wigs]
        rserder = eventing.receipt(pre=camHab.pre,
                                   sn=camHab.kever.sn,
                                   said=camHab.kever.serder.said)
        camRotWitRctMsg = eventing.messagize(serder=rserder, wigers=wigers)
        assert len(camRotWitRctMsg) == 413
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            parsing.Parser().parse(ims=bytearray(camRotWitRctMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camRotWitRctMsg))  # send copy of witness rcts
            assert len(kvy.db.getWigs(dgkey)) == 3  # fully witnessed
            assert len(kvy.cues) == 0  # no cues

        # send Cam's rot and wit receipts to Van
        # vanKvy.process(ims=bytearray(camRotMsg))  # should escrow since not witnesses
        # vanKvy.process(ims=bytearray(camRotWitRctMsg))
        # vanKvy.processEscrows()
        # assert vcKvr.sn == 2
        # assert vcKvr.wits == camHab.kever.wits

        # send Cam rot's witness rcts to Van first then send Cam rot
        parsing.Parser().parse(ims=bytearray(camRotWitRctMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camRotWitRctMsg))
        vanKvy.processEscrows()
        assert vcKvr.sn == 1
        parsing.Parser().parse(ims=bytearray(camRotMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camRotMsg))  # should escrow since not witnesses
        assert vcKvr.sn == 1
        vanKvy.processEscrows()
        assert vcKvr.sn == 2
        assert vcKvr.wits == camHab.kever.wits

        # need disjoint test of sending witness receipts to Van not conjoint
        # from Cam replay

    assert not os.path.exists(wokKS.path)
    assert not os.path.exists(wokDB.path)
    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)
    assert not os.path.exists(vanKS.path)
    assert not os.path.exists(vanDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)

    """End Test"""


def test_nonindexed_witness_receipts():
    """
    Test event validation logic with witnesses on incept message

    cam is controller
    van is validator
    wes is a witness
    wok is a witness
    wam is a witness

    """
    salt = coring.Salter(raw=b'abcdef0123456789').qb64

    with basing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
            basing.openDB(name="van") as vanDB, keeping.openKS(name="van") as vanKS, \
            basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
            basing.openDB(name="wok") as wokDB, keeping.openKS(name="wok") as wokKS, \
            basing.openDB(name="wam") as wamDB, keeping.openKS(name="wam") as wamKS, \
            basing.openDB(name="wil") as wilDB, keeping.openKS(name="wil") as wilKS:

        # witnesses first so can setup inception event for cam
        wsith = 1
        # setup Wes's habitat nontrans
        # Wes's receipts will be rcts with a receipt couple attached

        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wesHab.ks == wesKS
        assert wesHab.db == wesDB
        assert not wesHab.kever.prefixer.transferable
        # create non-local kevery for Wes to process nonlocal msgs
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)

        # setup Wok's habitat nontrans
        # Wok's receipts will be rcts with a receipt couple attached
        wokHab = habbing.Habitat(name='wok', ks=wokKS, db=wokDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wokHab.ks == wokKS
        assert wokHab.db == wokDB
        assert not wokHab.kever.prefixer.transferable
        # create non-local kevery for Wok to process nonlocal msgs
        wokKvy = eventing.Kevery(db=wokHab.db, lax=False, local=False)

        # setup Wam's habitat nontrans
        # Wams's receipts will be rcts with a receipt couple attached
        wamHab = habbing.Habitat(name='wam', ks=wamKS, db=wamDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wamHab.ks == wamKS
        assert wamHab.db == wamDB
        assert not wamHab.kever.prefixer.transferable
        # create non-local kevery for Wam to process nonlocal msgs
        wamKvy = eventing.Kevery(db=wamHab.db, lax=False, local=False)

        # setup Wil's habitat nontrans
        # Wil's receipts will be rcts with a receipt couple attached
        wilHab = habbing.Habitat(name='wil', ks=wilKS, db=wilDB,
                                 isith=wsith, icount=1,
                                 salt=salt, transferable=False, temp=True)  # stem is .name
        assert wilHab.ks == wilKS
        assert wilHab.db == wilDB
        assert not wilHab.kever.prefixer.transferable
        # create non-local kevery for Wam to process nonlocal msgs
        wilKvy = eventing.Kevery(db=wilHab.db, lax=False, local=False)

        # setup Cam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre, wamHab.pre]
        csith = 2  # hex str of threshold int
        camHab = habbing.Habitat(name='cam', ks=camKS, db=camDB,
                                 isith=csith, icount=3,
                                 toad=2, wits=wits,
                                 salt=salt, temp=True)  # stem is .name
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable
        assert len(camHab.iserder.werfers) == len(wits)
        for werfer in camHab.iserder.werfers:
            assert werfer.qb64 in wits
        assert camHab.kever.wits == wits
        assert camHab.kever.toad == 2
        assert camHab.kever.sn == 0

        # create non-local kevery for Cam to process non-local msgs
        camKvy = eventing.Kevery(db=camHab.db, lax=False, local=False)

        # setup Van's habitat trans multisig
        vsith = 2  # two of three signing threshold
        vanHab = habbing.Habitat(name='van', ks=vanKS, db=vanDB,
                                 isith=vsith, icount=3,
                                 salt=salt, temp=True)  # stem is .name
        assert vanHab.ks == vanKS
        assert vanHab.db == vanDB
        assert vanHab.kever.prefixer.transferable
        # create non-local kevery for Van to process nonlocal msgs
        vanKvy = eventing.Kevery(db=vanHab.db, lax=False, local=False)

        # make list so easier to batch
        camWitKvys = [wesKvy, wokKvy, wamKvy]  # nonlocal Keveries
        camWitHabs = [wesHab, wokHab, wamHab]

        # Create Cam inception and send to each of Cam's witnesses
        camIcpMsg = camHab.makeOwnInception()
        rctMsgs = []  # list of receipts from each witness
        for i, kvy in enumerate(camWitKvys):
            parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=kvy)
            # accepted event with cam sigs since own witness
            assert kvy.kevers[camHab.pre].sn == 0
            assert len(kvy.cues) == 1  # queued receipt cue
            rctMsg = camWitHabs[i].processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 617
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # Cam process rct msgs from all witnesses
            parsing.Parser().parse(ims=bytearray(msg), kvy=camKvy)
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # send receipts one at a time to Van to escrow. Van not yet recieved
        # icp event from Cam so not accepted Cam's pre
        # compute keys for latest event in Cam's key state
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.said)
        snkey = dbing.snKey(pre=camHab.pre, sn=camHab.kever.serder.sn)
        # Van process rct msgs from all witnesses for Cam's icp message
        for i, msg in enumerate(rctMsgs):
            parsing.Parser().parse(ims=bytearray(msg), kvy=vanKvy)
            # escrows to Ure
            assert vanKvy.db.cntUres(snkey) == i + 1  # escrows
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # all in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert camHab.pre not in vanKvy.kevers  # not accepted
        for hab in camWitHabs:  # Van accepted icp events for Cam's witnesses
            assert hab.pre in vanKvy.kevers

        vanKvy.processEscrows()  # process escrows
        assert vanKvy.db.cntPwes(snkey) == 0  # nothing in partial witness escrow
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # still in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert camHab.pre not in vanKvy.kevers  # still not accepted

        # Van process icp message from Cam
        parsing.Parser().parse(ims=bytearray(camIcpMsg), kvy=vanKvy)
        # event accepted in database with sigs but not into KEL
        assert vanKvy.db.cntSigs(dgkey) == len(camHab.kever.verfers)
        assert vanKvy.db.cntPwes(snkey) == 1  # now in partial witness escrow
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # still in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert camHab.pre not in vanKvy.kevers  # not accepted

        vanKvy.processEscrows()  # process escrows
        assert vanKvy.db.cntPwes(snkey) == 0  # unescrowed from first stage
        assert vanKvy.db.cntUres(snkey) == 0  # out of first stage
        assert vanKvy.db.cntWigs(dgkey) == len(rctMsgs)  # all wigs out now
        assert camHab.pre in vanKvy.kevers  # accepted

        vcKvr = vanKvy.kevers[camHab.pre]  # now Van has key state for Cam
        assert vcKvr.sn == 0
        assert vcKvr.wits == wits

        # Create Cam ixn and send to each of Cam's witnesses
        camIxnMsg = camHab.interact()
        rctMsgs = []  # list of receipts from each witness
        for i, kvy in enumerate(camWitKvys):
            parsing.Parser().parse(ims=bytearray(camIxnMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIxnMsg))  # send copy of cam icp msg to witness
            assert kvy.kevers[camHab.pre].sn == 1  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 281
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # Cam process rct msgs from all witnesses
            parsing.Parser().parse(ims=bytearray(msg), kvy=camKvy)
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # send receipts one at a time to Van to escrow.
        # Van not yet recieved ixn event from Cam but has accept icp event
        # compute keys for latest event in Cam's key state
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.said)
        snkey = dbing.snKey(pre=camHab.pre, sn=camHab.kever.serder.sn)
        # Van process rct msgs from all witnesses for Cam's ixn message
        for i, msg in enumerate(rctMsgs):
            parsing.Parser().parse(ims=bytearray(msg), kvy=vanKvy)
            # escrows to Ure
            assert vanKvy.db.cntUres(snkey) == i + 1  # escrows
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # all in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert vcKvr.sn == 0  # not ixn yet

        vanKvy.processEscrows()  # process escrows
        assert vanKvy.db.cntPwes(snkey) == 0  # nothing in partial witness escrow
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # still in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert vcKvr.sn == 0  # not ixn yet
        assert vcKvr.wits == wits  # no change

        # Van process ixn message from Cam
        parsing.Parser().parse(ims=bytearray(camIxnMsg), kvy=vanKvy)
        # event accepted in database with sigs but not into KEL
        assert vanKvy.db.cntSigs(dgkey) == len(camHab.kever.verfers)
        assert vanKvy.db.cntPwes(snkey) == 1  # now in partial witness escrow
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # still in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert vcKvr.sn == 0  # not accepted yet

        vanKvy.processEscrows()  # process escrows
        assert vanKvy.db.cntPwes(snkey) == 0  # unescrowed from first stage
        assert vanKvy.db.cntUres(snkey) == 0  # out of first stage
        assert vanKvy.db.cntWigs(dgkey) == len(rctMsgs)  # all wigs out now
        assert vcKvr.sn == 1  # ixn accepted
        assert vcKvr.wits == wits  # no change

        # Cam replace Wok with Wil as a witness.  But first setup Wil:
        #    Cam update Wil all event witnessed events for Cam by replay
        #    Cam update itself with Wil receipts including Wils inception
        camReplayMsg = camHab.replay()
        assert len(camReplayMsg) == 1933
        parsing.Parser().parse(ims=bytearray(camReplayMsg), kvy=wilKvy)

        assert camHab.pre in wilKvy.kevers
        assert wilKvy.kevers[camHab.pre].sn == 1  # asscepted both events
        assert len(wilKvy.cues) == 2
        wilRctMsg = wilHab.processCues(wilKvy.cues)  # process cue returns rct msg
        assert len(wilKvy.cues) == 0
        parsing.Parser().parse(ims=bytearray(wilRctMsg), kvy=camKvy)
        assert wilHab.pre in camKvy.kevers

        # Cam rotation with witness rotation
        camRotMsg = camHab.rotate(toad=2, cuts=[wokHab.pre], adds=[wilHab.pre])
        assert camHab.kever.wits == [wesHab.pre, wamHab.pre, wilHab.pre]
        assert camHab.kever.toad == 2
        assert camHab.kever.sn == 2

        # update wits
        oldwits = wits
        wits = camHab.kever.wits

        # update lists of witness kvys and habs
        camWitKvys = [wesKvy, wamKvy, wilKvy]
        camWitHabs = [wesHab, wamHab, wilHab]

        rctMsgs = []  # list of receipt msgs from each witness
        for i, kvy in enumerate(camWitKvys):
            parsing.Parser().parse(ims=bytearray(camRotMsg), kvy=kvy)
            assert kvy.kevers[camHab.pre].sn == 2  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 281
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:  # process rct msgs from all witnesses
            parsing.Parser().parse(ims=bytearray(msg), kvy=camKvy)
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # send receipts one at a time to Van to escrow.
        # Van not yet recieved rot event from Cam but has accepted icp & ixn events
        # compute keys for latest event in Cam's key state
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.said)
        snkey = dbing.snKey(pre=camHab.pre, sn=camHab.kever.serder.sn)
        # Van process rct msgs from all witnesses for Cam's ixn message
        for i, msg in enumerate(rctMsgs):
            parsing.Parser().parse(ims=bytearray(msg), kvy=vanKvy)
            # escrows to Ure
            assert vanKvy.db.cntUres(snkey) == i + 1  # escrows
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # all in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert vcKvr.sn == 1  # not rot yet

        # send stale receipts from Wil to Van
        parsing.Parser().parse(ims=bytearray(wilRctMsg), kvy=vanKvy)

        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # no change

        vanKvy.processEscrows()  # process escrows
        assert vanKvy.db.cntPwes(snkey) == 0  # nothing in partial witness escrow
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # still in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert vcKvr.sn == 1  # not rot yet
        assert vcKvr.wits == oldwits  # no change

        # Van process rot message from Cam
        parsing.Parser().parse(ims=bytearray(camRotMsg), kvy=vanKvy)
        # event accepted in database with sigs but not into KEL
        assert vanKvy.db.cntSigs(dgkey) == len(camHab.kever.verfers)
        assert vanKvy.db.cntPwes(snkey) == 1  # now in partial witness escrow
        assert vanKvy.db.cntUres(snkey) == len(rctMsgs)  # still in escrow
        assert vanKvy.db.cntWigs(dgkey) == 0  # no wigs yet
        assert vcKvr.sn == 1  # not accepted yet

        vanKvy.processEscrows()  # process escrows
        assert vanKvy.db.cntPwes(snkey) == 0  # unescrowed from first stage
        assert vanKvy.db.cntUres(snkey) == 0  # out of first stage
        assert vanKvy.db.cntWigs(dgkey) == len(rctMsgs)  # all wigs out now
        assert vcKvr.sn == 2  # rot accepted
        assert vcKvr.wits == wits  # wits changed

    assert not os.path.exists(wokKS.path)
    assert not os.path.exists(wokDB.path)
    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)
    assert not os.path.exists(vanKS.path)
    assert not os.path.exists(vanDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)

    """End Test"""


def test_out_of_order_witnessed_events():
    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes
    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
            basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
            basing.openDB(name="bam") as bamDB:

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1, transferable=False, temp=True)

        assert wesHab.pre == "BK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c"

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[wesHab.pre], temp=True)
        assert bobHab.pre == "EgJtvKj2tUD9K-t92Y_xkf0AGHIHwOmMqTZTy6dxrPUs"

        # Create Bob's icp, pass to Wes and generate receipt.
        wesKvy = eventing.Kevery(db=wesDB, lax=False, local=False)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy)
        assert bobHab.pre in wesHab.kevers
        iserder = coring.Serder(raw=bytearray(bobIcp))
        wesHab.receipt(serder=iserder)

        # Rotate and get Bob's rot, pass to Wes and generate receipt.
        bobHab.rotate()
        bobRotMsg = bobHab.makeOwnEvent(sn=1)
        parsing.Parser().parse(ims=bytearray(bobRotMsg), kvy=wesKvy)
        assert wesKvy.kevers[bobHab.pre].sn == 1
        bobRot = coring.Serder(raw=bobRotMsg)
        wesHab.receipt(serder=bobRot)

        # Get the receipted rotation event and pass, out of order to Bam
        msgs = bytearray()
        for msg in wesDB.clonePreIter(pre=bobHab.pre, fn=1):
            msgs.extend(msg)

        bamKvy = eventing.Kevery(db=bamDB, lax=False, local=False)
        parsing.Parser().parse(ims=msgs, kvy=bamKvy)

        # Ensure the rot ended up in out-of-order escrow
        assert bobHab.pre not in bamKvy.kevers
        oodig = bamDB.getOoes(dbing.snKey(bobHab.pre.encode("utf-8"), 1))
        assert bobRot.saidb == bytes(oodig[0])

        # Pass the icp to Bam, process escrows and see if the fully
        # receipted event lands in Bam's Kevery
        msg = wesDB.cloneEvtMsg(pre=bobHab.pre, fn=0, dig=iserder.saidb)

        parsing.Parser().parse(ims=msg, kvy=bamKvy)
        bamKvy.processEscrows()

        assert bobHab.pre in bamKvy.kevers
        assert bamKvy.kevers[bobHab.pre].sn == 1

        pwedig = bamDB.getPwes(dbing.snKey(bobHab.pre.encode("utf-8"), 1))
        assert pwedig == []




if __name__ == "__main__":
    test_nonindexed_witness_receipts()
