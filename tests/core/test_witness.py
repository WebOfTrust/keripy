# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os
import datetime

import pytest

from keri import help
from keri.help import helping
from keri.db import dbing
from keri.base import keeping, directing
from keri.core import coring, eventing


logger = help.ogler.getLogger()


def test_witness():
    """
    Test event validation logic with witnesses

    cam is controller
    van is validator
    wes is a witness
    wok is a witness
    wam is a witness

    """
    salt = coring.Salter(raw=b'abcdef0123456789').qb64

    with dbing.openDB(name="cam") as camDB, keeping.openKS(name="cam") as camKS, \
         dbing.openDB(name="van") as vanDB, keeping.openKS(name="van") as vanKS, \
         dbing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         dbing.openDB(name="wok") as wokDB, keeping.openKS(name="wok") as wokKS, \
         dbing.openDB(name="wam") as wamDB, keeping.openKS(name="wam") as wamKS, \
         dbing.openDB(name="wil") as wilDB, keeping.openKS(name="wil") as wilKS:

        # witnesses first so can setup inception event for cam
        wsith = 1
        # setup Wes's habitat nontrans
        # Wes's receipts will be rcts with a receipt couple attached

        wesHab = directing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wesHab.ks == wesKS
        assert wesHab.db == wesDB
        assert not wesHab.kever.prefixer.transferable
        # create non-local kevery for Wes to process nonlocal msgs
        wesKvy = eventing.Kevery(kevers=wesHab.kevers,
                                    db=wesHab.db,
                                    opre=wesHab.pre,
                                    local=False)

        # setup Wok's habitat nontrans
        # Wok's receipts will be rcts with a receipt couple attached
        wokHab = directing.Habitat(name='wok',ks=wokKS, db=wokDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wokHab.ks == wokKS
        assert wokHab.db == wokDB
        assert not wokHab.kever.prefixer.transferable
        # create non-local kevery for Wok to process nonlocal msgs
        wokKvy = eventing.Kevery(kevers=wokHab.kevers,
                                    db=wokHab.db,
                                    opre=wokHab.pre,
                                    local=False)

        # setup Wam's habitat nontrans
        # Wams's receipts will be rcts with a receipt couple attached
        wamHab = directing.Habitat(name='wam', ks=wamKS, db=wamDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wamHab.ks == wamKS
        assert wamHab.db == wamDB
        assert not wamHab.kever.prefixer.transferable
        # create non-local kevery for Wam to process nonlocal msgs
        wamKvy = eventing.Kevery(kevers=wamHab.kevers,
                                    db=wamHab.db,
                                    opre=wamHab.pre,
                                    local=False)

        # setup Wil's habitat nontrans
        # Wil's receipts will be rcts with a receipt couple attached
        wilHab = directing.Habitat(name='wil', ks=wilKS, db=wilDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wilHab.ks == wilKS
        assert wilHab.db == wilDB
        assert not wilHab.kever.prefixer.transferable
        # create non-local kevery for Wam to process nonlocal msgs
        wilKvy = eventing.Kevery(kevers=wilHab.kevers,
                                    db=wilHab.db,
                                    opre=wilHab.pre,
                                    local=False)

        # setup Cam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre, wamHab.pre]
        csith = 2  # hex str of threshold int
        camHab = directing.Habitat(name='cam', ks=camKS, db=camDB,
                                   isith=csith, icount=3,
                                   toad=2, wits=wits,
                                   salt=salt, temp=True)  # stem is .name
        assert camHab.ks == camKS
        assert camHab.db == camDB
        assert camHab.kever.prefixer.transferable
        for werfer in camHab.iserder.werfers:
            assert werfer.qb64 in wits
        assert camHab.kever.wits == wits
        assert camHab.kever.toad == 2
        assert camHab.kever.sn == 0

        # create non-local kevery for Cam to process onlocal msgs
        camKvy = eventing.Kevery(kevers=camHab.kevers,
                                    db=camHab.db,
                                    opre=camHab.pre,
                                    local=False)

        # setup Van's habitat trans multisig
        vsith = 2  # two of three signing threshold
        vanHab = directing.Habitat(name='van', ks=vanKS, db=vanDB,
                                   isith=vsith, icount=3,
                                   salt=salt, temp=True)  # stem is .name
        assert vanHab.ks == vanKS
        assert vanHab.db == vanDB
        assert vanHab.kever.prefixer.transferable
        # create non-local kevery for Van to process nonlocal msgs
        vanKvy = eventing.Kevery(kevers=vanHab.kevers,
                                    db=vanHab.db,
                                    opre=vanHab.pre,
                                    local=False)

        # make list so easier to batch
        camWitKvys = [wesKvy, wokKvy, wamKvy]
        camWitHabs = [wesHab, wokHab, wamHab]

        # Create Cam inception and send to each of Cam's witnesses
        camIcpMsg = camHab.makeOwnInception()
        rctMsgs = []  # list of receipts from each witness
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            eventing.Parser().process(ims=bytearray(camIcpMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIcpMsg))  # send copy of cam icp msg to witness
            assert kvy.kevers[camHab.pre].sn == 0  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 566
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:# process rct msgs from all witnesses
            eventing.Parser().process(ims=bytearray(msg), kvy=camKvy)
            # camKvy.process(ims=bytearray(msg))  # make copy
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # get from Cam database copies of witness receipts received by Cam
        # and send to witnesses so all witnesses have full set of receipts
        # from all other witnesses
        # reply one event or receipt one event with all witness attachments
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.dig)
        wigs = camHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigers = [coring.Siger(qb64b=bytes(wig)) for wig in  wigs]
        rserder = eventing.receipt(pre=camHab.pre,
                                   sn=camHab.kever.sn,
                                   dig=camHab.kever.serder.dig)
        camIcpWitRctMsg = eventing.messagize(serder=rserder, wigers=wigers)
        assert len(camIcpWitRctMsg) == 413
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            eventing.Parser().process(ims=bytearray(camIcpWitRctMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIcpWitRctMsg))  # send copy of witness rcts
            assert len(kvy.db.getWigs(dgkey)) == 3  # fully witnessed
            assert len(kvy.cues) == 0  # no cues

        # send Cam icp and witness rcts to Van
        eventing.Parser().process(ims=bytearray(camIcpMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camIcpMsg))  # should escrow since not witnesses
        assert camHab.pre not in vanKvy.kevers
        eventing.Parser().process(ims=bytearray(camIcpWitRctMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camIcpWitRctMsg))
        vanKvy.processEscrows()
        assert camHab.pre in vanKvy.kevers
        vcKvr = vanKvy.kevers[camHab.pre]
        assert vcKvr.sn == 0
        assert vcKvr.wits == wits

        # Create Cam ixn and send to each of Cam's witnesses
        camIxnMsg = camHab.interact()
        rctMsgs = []  # list of receipts from each witness
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            eventing.Parser().process(ims=bytearray(camIxnMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIxnMsg))  # send copy of cam icp msg to witness
            assert kvy.kevers[camHab.pre].sn == 1  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 281
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:# process rct msgs from all witnesses
            eventing.Parser().process(ims=bytearray(msg), kvy=camKvy)
            # camKvy.process(ims=bytearray(msg))  # make copy
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # get from Cam database copies of witness receipts received by Cam
        # and send to witnesses so all witnesses have full set of receipts
        # from all other witnesses
        # reply one event or receipt one event with all witness attachments
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.dig)
        wigs = camHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigers = [coring.Siger(qb64b=bytes(wig)) for wig in  wigs]
        rserder = eventing.receipt(pre=camHab.pre,
                                   sn=camHab.kever.sn,
                                   dig=camHab.kever.serder.dig)
        camIxnWitRctMsg = eventing.messagize(serder=rserder, wigers=wigers)
        assert len(camIxnWitRctMsg) == 413
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            eventing.Parser().process(ims=bytearray(camIxnWitRctMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camIxnWitRctMsg))  # send copy of witness rcts
            assert len(kvy.db.getWigs(dgkey)) == 3  # fully witnessed
            assert len(kvy.cues) == 0  # no cues

        # send Cam ixn's witness rcts to Van first then send Cam ixn
        eventing.Parser().process(ims=bytearray(camIxnWitRctMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camIxnWitRctMsg))
        vanKvy.processEscrows()
        assert vcKvr.sn == 0
        eventing.Parser().process(ims=bytearray(camIxnMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camIxnMsg))  # should escrow since not witnesses
        assert vcKvr.sn == 0
        vanKvy.processEscrows()
        assert vcKvr.sn == 1

        # Cam replace Wok with Wil as a witness.
        # Cam update Wil all event witnessed events for Cam by replay
        # Cam update itself with Wil receipts including Wils inception
        camReplayMsg = camHab.replay()
        assert len(camReplayMsg) == 1831
        eventing.Parser().process(ims=bytearray(camReplayMsg), kvy=wilKvy)
        # wilKvy.process(ims=bytearray(camReplayMsg))
        assert camHab.pre in wilKvy.kevers
        assert wilKvy.kevers[camHab.pre].sn == 1  # asscepted both events
        assert len(wilKvy.cues) == 2
        wilRctMsg = wilHab.processCues(wilKvy.cues)  # process cue returns rct msg
        assert len(wilKvy.cues) == 0
        eventing.Parser().process(ims=bytearray(wilRctMsg), kvy=camKvy)
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
            eventing.Parser().process(ims=bytearray(camRotMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camRotMsg))  # send copy of cam msg to witness
            assert kvy.kevers[camHab.pre].sn == 2  # accepted event
            assert len(kvy.cues) == 1  # queued receipt cue
            hab = camWitHabs[i]
            rctMsg = hab.processCues(kvy.cues)  # process cue returns rct msg
            assert len(rctMsg) == 281
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:# process rct msgs from all witnesses
            eventing.Parser().process(ims=bytearray(msg), kvy=camKvy)
            # camKvy.process(ims=bytearray(msg))  # make copy
        for hab in camWitHabs:
            assert hab.pre in camKvy.kevers

        # get from Cam database copies of witness receipts received by Cam
        # and send to witnesses so all witnesses have full set of receipts
        # from all other witnesses
        # reply one event or receipt one event with all witness attachments
        dgkey = dbing.dgKey(pre=camHab.pre, dig=camHab.kever.serder.dig)
        wigs = camHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigers = [coring.Siger(qb64b=bytes(wig)) for wig in  wigs]
        rserder = eventing.receipt(pre=camHab.pre,
                                   sn=camHab.kever.sn,
                                   dig=camHab.kever.serder.dig)
        camRotWitRctMsg = eventing.messagize(serder=rserder, wigers=wigers)
        assert len(camRotWitRctMsg) == 413
        for i in range(len(camWitKvys)):
            kvy = camWitKvys[i]
            eventing.Parser().process(ims=bytearray(camRotWitRctMsg), kvy=kvy)
            # kvy.process(ims=bytearray(camRotWitRctMsg))  # send copy of witness rcts
            assert len(kvy.db.getWigs(dgkey)) == 3  # fully witnessed
            assert len(kvy.cues) == 0  # no cues

        # send Cam's rot and wit receipts to Van
        #vanKvy.process(ims=bytearray(camRotMsg))  # should escrow since not witnesses
        #vanKvy.process(ims=bytearray(camRotWitRctMsg))
        #vanKvy.processEscrows()
        #assert vcKvr.sn == 2
        #assert vcKvr.wits == camHab.kever.wits


        # send Cam rot's witness rcts to Van first then send Cam rot
        eventing.Parser().process(ims=bytearray(camRotWitRctMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camRotWitRctMsg))
        vanKvy.processEscrows()
        assert vcKvr.sn == 1
        eventing.Parser().process(ims=bytearray(camRotMsg), kvy=vanKvy)
        # vanKvy.process(ims=bytearray(camRotMsg))  # should escrow since not witnesses
        assert vcKvr.sn == 1
        vanKvy.processEscrows()
        assert vcKvr.sn == 2
        assert vcKvr.wits == camHab.kever.wits



    assert not os.path.exists(wokKS.path)
    assert not os.path.exists(wokDB.path)
    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)
    assert not os.path.exists(vanKS.path)
    assert not os.path.exists(vanDB.path)
    assert not os.path.exists(camKS.path)
    assert not os.path.exists(camDB.path)

    """End Test"""


if __name__ == "__main__":
    test_witness()
