# -*- encoding: utf-8 -*-
"""
tests.app.grouping module

"""
from contextlib import contextmanager

import time
from hio.base import doing, tyming

from keri.app import habbing, grouping, storing, notifying
from keri.core import coring, eventing, parsing
from keri.db import dbing, basing
from keri.peer import exchanging


def test_counselor():
    salt = b'0123456789abcdef'
    prefix = "counselor"
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True) as (hby3, hab3):
        counselor = grouping.Counselor(hby=hby1)

        # Keverys so we can process each other's inception messages.
        kev1 = eventing.Kevery(db=hab1.db, lax=True, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=True, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=True, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None  # need to fixe this
        inits = dict(isith='2', nsith='2', toad=0, wits=[])

        # Create group hab with init params
        ghab = hby1.makeGroupHab(group=f"{prefix}_group1", mhab=hab1,
                                 smids=smids, rmids=rmids, **inits)
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=prefixer.qb64)

        # Send to Counselor to post process through escrows
        counselor.start(prefixer=prefixer, seqner=seqner, saider=saider,
                        mid=hab1.pre, smids=smids, rmids=rmids)
        assert len(counselor.postman.evts) == 2  # Send my event to other participants
        evt = counselor.postman.evts.popleft()
        assert evt["src"] == "EOzS8kvK5AM0O9Qwub8wDVAmuetGCtUYVOQC6vpqbLQa"
        assert evt["dest"] == "EHTApV7zY0866EBv6891tN19uM9TnbwpvV0JzcWu1DVY"
        assert evt["serder"].raw == (b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EFHbsKUAMxGqGinFKsuEHW0afydw9y474RJb'
                                     b'coNBES3s","i":"EFHbsKUAMxGqGinFKsuEHW0afydw9y474RJbcoNBES3s","s":"0","kt":"2'
                                     b'","k":["DEXdkHRR2Nspj5czsFvKOa-ZnGzMMFG5MLaBle19aJ9j","DL4SFzA89ls_auIqISf4U'
                                     b'bSQGxNPc9y8Z2UrPDZupEsM","DERxxjBQUD4nGiaioBlqg8qpkRjJLGMe67OPdVsHFarQ"],"nt'
                                     b'":"2","n":["EKMBA8Q1uP3WshghLR_r6MjYwVEids8yKb_03w8FOOFO","EHV8V6dj_VXvXZFUw'
                                     b'MTT4yUy40kw5uYMXnFxoh_KZmos","EMUrvGYprwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJUn"]'
                                     b',"bt":"0","b":[],"c":[],"a":[]}')
        (seqner, saider) = hby1.db.gpse.getLast(keys=(ghab.pre,))  # Escrowed the event for sigs
        assert seqner.sn == 0
        assert saider.qb64 == "EFHbsKUAMxGqGinFKsuEHW0afydw9y474RJbcoNBES3s"

        # Sith 2 so create second signature to get past the first escrow
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        evt = grouping.getEscrowedEvent(hab2.db, ghab2.pre, 0)
        assert evt == (b'{"v":"KERI10JSON0001e7_","t":"icp","d":"EFHbsKUAMxGqGinFKsuEHW0a'
                       b'fydw9y474RJbcoNBES3s","i":"EFHbsKUAMxGqGinFKsuEHW0afydw9y474RJbc'
                       b'oNBES3s","s":"0","kt":"2","k":["DEXdkHRR2Nspj5czsFvKOa-ZnGzMMFG5'
                       b'MLaBle19aJ9j","DL4SFzA89ls_auIqISf4UbSQGxNPc9y8Z2UrPDZupEsM","DE'
                       b'RxxjBQUD4nGiaioBlqg8qpkRjJLGMe67OPdVsHFarQ"],"nt":"2","n":["EKMB'
                       b'A8Q1uP3WshghLR_r6MjYwVEids8yKb_03w8FOOFO","EHV8V6dj_VXvXZFUwMTT4'
                       b'yUy40kw5uYMXnFxoh_KZmos","EMUrvGYprwKm77Oju22TlcoAEhL9QnnYfOBFPO'
                       b'1IyJUn"],"bt":"0","b":[],"c":[],"a":[]}-AABABCNm6zWv-4VPHlK_yoBU'
                       b'CDKPUbJceFPrWZFNl8oKgg2mNPquCimuPxIYDC8WJVmpPaXK9CwjYihzpVNeuHHI'
                       b'qcN')

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 to process all sigs together

        counselor.processEscrows()
        val = hby1.db.gpse.getLast(keys=(ghab.pre,))  # thold met, partial sig escrow should be empty
        assert val is None
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)
        counselor.postman.evts.popleft()

        # Partial rotation
        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None  # need to fix
        counselor.rotate(ghab=ghab, smids=smids, rmids=rmids,
                         nsith='2', toad=0, cuts=list(), adds=list())
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.smids == smids
        assert rec.nsith == '2'
        assert rec.toad == 0

        counselor.processEscrows()  # process escrows to get witness-less event to next step
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is None
        assert len(counselor.postman.evts) == 2
        evt = counselor.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab2.pre
        assert evt["topic"] == "multisig"
        assert evt["serder"].raw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EEX9vGqk8FJbe-pSusdW-t6dtTyPeOgtR8Cd'
                                     b'hue6LgY7","i":"EOzS8kvK5AM0O9Qwub8wDVAmuetGCtUYVOQC6vpqbLQa","s":"1","p":"EO'
                                     b'zS8kvK5AM0O9Qwub8wDVAmuetGCtUYVOQC6vpqbLQa","kt":"1","k":["DEbwF934m5TjdQbC1'
                                     b'8jSmk2CcPO7xzAemzePy4LKnA_U"],"nt":"1","n":["EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHP'
                                     b'EZ08zMICPhPTw"],"bt":"0","br":[],"ba":[],"a":[]}')
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.smids == smids

        # rotate second identifiter in group, process escrows to generate group rotation event.
        hab2.rotate()
        rot = hab2.makeOwnEvent(sn=1)
        parsing.Parser().parse(ims=bytearray(rot), kvy=kev1)  # parse rotation
        counselor.processEscrows()  # second identifier has rotated, second stage clear
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is None

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 1
        assert saider.qb64b == b'ECmJe44VLyThxwh5vCAlt_GVuMMbeQD3A8z9AtEShKTF'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (b'{"v":"KERI10JSON0001ed_","t":"rot","d":"ECmJe44VLyThxwh5vCAlt_GVuMMbeQD3A8z9'
                              b'AtEShKTF","i":"EFHbsKUAMxGqGinFKsuEHW0afydw9y474RJbcoNBES3s","s":"1","p":"EF'
                              b'HbsKUAMxGqGinFKsuEHW0afydw9y474RJbcoNBES3s","kt":"2","k":["DEbwF934m5TjdQbC1'
                              b'8jSmk2CcPO7xzAemzePy4LKnA_U","DBL_WnUsuY-CbIFNkME8dYG0lMSNtT993IWcmsPoUuED"]'
                              b',"nt":"2","n":["EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ08zMICPhPTw","EGyO8jUZpLIlA'
                              b'CoeLmfUzvE3mnxmcU2m_nyKfSDfpxV4","EMUrvGYprwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJ'
                              b'Un"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = coring.Serder(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON0001ed_","t":"rot","d":"ECmJe44VLyThxwh5vCAlt_GV'
                       b'uMMbeQD3A8z9AtEShKTF","i":"EFHbsKUAMxGqGinFKsuEHW0afydw9y474RJbc'
                       b'oNBES3s","s":"1","p":"EFHbsKUAMxGqGinFKsuEHW0afydw9y474RJbcoNBES'
                       b'3s","kt":"2","k":["DEbwF934m5TjdQbC18jSmk2CcPO7xzAemzePy4LKnA_U"'
                       b',"DBL_WnUsuY-CbIFNkME8dYG0lMSNtT993IWcmsPoUuED"],"nt":"2","n":["'
                       b'EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ08zMICPhPTw","EGyO8jUZpLIlACoeL'
                       b'mfUzvE3mnxmcU2m_nyKfSDfpxV4","EMUrvGYprwKm77Oju22TlcoAEhL9QnnYfO'
                       b'BFPO1IyJUn"],"bt":"0","br":[],"ba":[],"a":[]}-AABABCdRDo4RsFYSpj'
                       b'YvFai31ajkT7qpwKFuCSQboCFIJ9T8iP462ltRgL-FbNb-YbybQFamTa23vqn7ve'
                       b'Es4w9C1UK')

        # Create group rotation from second participant

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)

        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64]
        ndigs = [hab1.kever.nexter.digs[0], hab2.kever.nexter.digs[0], hab3.kever.nexter.digs[0]]
        assert ghab.kever.sn == 1
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert ghab.kever.nexter.digs == ndigs


@contextmanager
def openMultiSig(prefix="test", salt=b'0123456789abcdef', temp=True, **kwa):
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=temp) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=temp) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=temp) as (hby3, hab3):
        # Keverys so we can process each other's inception messages.
        kev1 = eventing.Kevery(db=hab1.db, lax=True, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=True, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=True, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None


        inits = dict(
            toad=0,
            wits=[],
            isith='3',
            nsith='3'
        )

        ghab1 = hby1.makeGroupHab(group=f"{prefix}_group1", mhab=hab1,
                                  smids=smids, rmids=rmids, **inits)
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids,**inits)
        ghab3 = hby3.makeGroupHab(group=f"{prefix}_group3", mhab=hab3,
                                  smids=smids, rmids=rmids, **inits)

        dgkey = dbing.dgKey(ghab1.pre.encode("utf-8"), ghab1.pre.encode("utf-8"))  # digest key
        eraw = hab1.db.getEvt(dgkey)
        sigs = bytearray()
        sigs.extend(bytes(hab1.db.getSigs(dgkey)[0]))
        sigs.extend(bytes(hab2.db.getSigs(dgkey)[0]))
        sigs.extend(bytes(hab3.db.getSigs(dgkey)[0]))

        evt = bytearray(eraw)
        evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=3).qb64b)  # attach cnt
        evt.extend(sigs)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)

        assert ghab1.pre in kev1.kevers
        assert ghab1.pre in kev2.kevers
        assert ghab1.pre in kev3.kevers

        yield (hby1, ghab1), (hby2, ghab2), (hby3, ghab3)


def test_multisig_incept(mockHelpingNowUTC):
    with habbing.openHab(name="test", temp=True) as (hby, hab):
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        exn, atc = grouping.multisigInceptExn(hab=hab, aids=aids, ked=hab.kever.serder.ked)

        assert exn.ked["r"] == '/multisig/icp'
        assert exn.saidb == b'EEl70ZAj2v8kR8X2IkKB2tuhhYa4lHSO1UqvA3_cZK7G'
        assert atc == (b'-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB-u_h6NLNe'
                       b'MVCh3k07dY7smtLV4MhGD-Fgl3IAuJOIa2IpNYGG_YsvfD4GLcv1zU1btNHmnfXm'
                       b'OdoKbaTOY_YH')
        data = exn.ked["a"]
        assert data["aids"] == aids
        assert data["ked"] == hab.kever.serder.ked


def test_multisig_rotate(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):
        exn, atc = grouping.multisigRotateExn(ghab=ghab1, aids=ghab1.smids, isith='2', toad=0, cuts=[],
                                              adds=[], data=[])

        assert exn.ked["r"] == '/multisig/rot'
        assert exn.saidb == b'EEheekL5ct-RK_-4xx7Yj3Nxj0WZY3JyXGN8ZMD8IxmH'
        assert atc == (b'-HABEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkaba-AABAADFjbd96xYB'
                       b'BjLD4vux9EET7vTUvS7lxY6gUHKehU-SiaHX3hiW9cbRy5iKv56k7QQjp5cSWKw7'
                       b'SF4q9J5_yN4O')

        data = exn.ked["a"]
        assert data["aids"] == ghab1.smids
        assert data["gid"] == ghab1.pre
        assert data["isith"] == '2'
        assert data["toad"] == 0
        assert data["cuts"] == []
        assert data["adds"] == []
        assert data["data"] == []


def test_multisig_interact(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):
        exn, atc = grouping.multisigInteractExn(ghab=ghab1, aids=ghab1.smids,
                                                data=[{"i": 1, "x": 0, "d": 2}])

        assert exn.ked["r"] == '/multisig/ixn'
        assert exn.saidb == b'EN9CoGmdCd8fNaYK3FrYUJhmJHL7aZ3OhFZzEutJ5xZZ'
        assert atc == (b'-HABEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkaba-AABAABKPpOh4dSt'
                       b'geh8iLU95Vk9dtOyvCujQu6zsy0a5cvHctgew_acCv4ZAT_oYneVBDkPnEdcdFJW'
                       b'wlqtQ784zK4L')
        data = exn.ked["a"]
        assert data["aids"] == ghab1.smids
        assert data["gid"] == ghab1.pre
        assert data["data"] == [{"i": 1, "x": 0, "d": 2}]


def test_multisig_incept_handler(mockHelpingNowUTC):
    ctrl = "EIwLgWhrDj2WI4WCiArWVAYsarrP-B48OM4T6_Wk6BLs"
    with habbing.openHab(name="test0", temp=True) as (hby, hab):

        aids = [hab.pre, "EArzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        serder = eventing.incept(keys=["DAEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"],
                                 ndigs=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"])

        notifier = notifying.Notifier(hby=hby)
        handler = grouping.MultisigInceptHandler(hby=hby, notifier=notifier)

        # Pass message missing keys:
        handler.msgs.append(dict(name="value"))
        handler.msgs.append(dict(pre=hab.kever.prefixer))
        handler.msgs.append(dict(pre=hab.kever.prefixer, payload=dict(aids=aids)))
        handler.msgs.append(dict(pre=hab.kever.prefixer, payload=dict(aids=aids, ked=serder.ked)))

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[handler])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        assert len(notifier.signaler.signals) == 1
        doist.exit()

    with habbing.openHab(name="test0", temp=True) as (hby, hab):

        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        exn, atc = grouping.multisigInceptExn(hab=hab, aids=aids, ked=hab.kever.serder.ked)

        notifier = notifying.Notifier(hby=hby)
        exc = exchanging.Exchanger(db=hby.db, handlers=[])
        grouping.loadHandlers(hby=hby, exc=exc, notifier=notifier)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[exc])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        assert len(notifier.signaler.signals) == 1


def test_multisig_rotate_handler(mockHelpingNowUTC):
    ctrl = "EIwLgWhrDj2WI4WCiArWVAYsarrP-B48OM4T6_Wk6BLs"
    with openMultiSig(prefix="test") as ((hby, ghab), (_, _), (_, _)):

        notifier = notifying.Notifier(hby=hby)
        handler = grouping.MultisigRotateHandler(hby=hby, notifier=notifier)

        # Pass message missing keys:
        handler.msgs.append(dict(name="value"))
        handler.msgs.append(dict(pre=ghab.kever.prefixer))
        handler.msgs.append(dict(pre=ghab.kever.prefixer, payload=dict(aids=ghab.smids)))
        handler.msgs.append(dict(pre=ghab.kever.prefixer, payload=dict(aids=ghab.smids, gid=ghab.pre)))
        handler.msgs.append(dict(pre=ghab.mhab.kever.prefixer, payload=dict(aids=ghab.smids, gid=ghab.pre)))

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[handler])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        assert len(notifier.signaler.signals) == 1

    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):

        exn, atc = grouping.multisigRotateExn(ghab=ghab1, aids=ghab1.smids, isith='2', toad=0, cuts=[],
                                              adds=[], data=[])
        notifier = notifying.Notifier(hby=hby1)
        exc = exchanging.Exchanger(db=hby1.db, handlers=[])
        grouping.loadHandlers(hby=hby1, exc=exc, notifier=notifier)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[exc])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        assert len(notifier.signaler.signals) == 1


def test_multisig_interact_handler(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby, ghab), (_, _), (_, _)):

        notifier = notifying.Notifier(hby=hby)
        handler = grouping.MultisigInteractHandler(hby=hby, notifier=notifier)

        # Pass message missing keys:
        handler.msgs.append(dict(name="value"))
        handler.msgs.append(dict(pre=ghab.kever.prefixer))
        handler.msgs.append(dict(pre=ghab.kever.prefixer, payload=dict(aids=ghab.smids)))
        handler.msgs.append(dict(pre=ghab.kever.prefixer, payload=dict(aids=ghab.smids, gid=ghab.pre)))
        handler.msgs.append(dict(pre=ghab.mhab.kever.prefixer, payload=dict(aids=ghab.smids, gid=ghab.pre)))

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[handler])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        assert len(notifier.signaler.signals) == 1

    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):

        exn, atc = grouping.multisigInteractExn(ghab=ghab1, aids=ghab1.smids,
                                                data=[{"i": 1, "x": 0, "d": 2}])

        notifier = notifying.Notifier(hby=hby1)
        exc = exchanging.Exchanger(db=hby1.db, handlers=[])
        grouping.loadHandlers(hby=hby1, exc=exc, notifier=notifier)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[exc])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        assert len(notifier.signaler.signals) == 1


def test_pending_events():
    with habbing.openHab(name="test0", temp=True) as (hby, hab):
        counselor = grouping.Counselor(hby=hby)

        rec = basing.RotateRecord(
            sn=0,
            isith=["1/2, 1/2, 1/2"],
            nsith=["1/2, 1/2, 1/2"],
            toad=3,
            cuts=[],
            adds=[],
            data=[dict(a=1)],
            date="2021-06-09T17:35:54.169967+00:00",
            smids=[hab.pre]
        )
        hby.db.gpae.put(keys=(hab.pre,), val=rec)

        evts = counselor.pendingEvents(hab.pre)
        assert len(evts) == 1
        assert evts[0] == {'adds': [],
                           'aids': ['EFPnKh_K7OrV7giJWjUVM7QIZftaCdPQnTQBOGIviMrj'],
                           'cuts': [],
                           'data': [{'a': 1}],
                           'isith': ['1/2, 1/2, 1/2'],
                           'nsith': ['1/2, 1/2, 1/2'],
                           'sn': 0,
                           'timestamp': '2021-06-09T17:35:54.169967+00:00',
                           'toad': 3}

        rec = basing.RotateRecord(
            sn=3,
            isith=['1/2, 1/2, 1/2'],
            nsith="1",
            toad=1,
            cuts=[],
            adds=[],
            data=[],
            date="2021-06-09T17:35:54.169967+00:00",
            smids=[hab.pre]
        )
        hby.db.glwe.put(keys=(hab.pre,), val=rec)
        evts = counselor.pendingEvents(hab.pre)
        assert len(evts) == 2
        assert evts[1] == {'adds': [],
                           'aids': ['EFPnKh_K7OrV7giJWjUVM7QIZftaCdPQnTQBOGIviMrj'],
                           'cuts': [],
                           'data': [],
                           'isith': ['1/2, 1/2, 1/2'],
                           'nsith': '1',
                           'sn': 3,
                           'timestamp': '2021-06-09T17:35:54.169967+00:00',
                           'toad': 1}

        evts = counselor.pendingEvents("ABC")
        assert len(evts) == 0
