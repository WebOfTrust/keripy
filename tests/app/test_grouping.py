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
        inits = dict(isith='["1/2", "1/2", "1/2"]', nsith='["1/2", "1/2", "1/2"]', toad=0, wits=[])

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
        assert evt["serder"].raw == (b'{"v":"KERI10JSON000207_","t":"icp","d":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2'
                                     b'vDS1EVAS","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"0","kt":["'
                                     b'1/2","1/2","1/2"],"k":["DEXdkHRR2Nspj5czsFvKOa-ZnGzMMFG5MLaBle19aJ9j","DL4SF'
                                     b'zA89ls_auIqISf4UbSQGxNPc9y8Z2UrPDZupEsM","DERxxjBQUD4nGiaioBlqg8qpkRjJLGMe67'
                                     b'OPdVsHFarQ"],"nt":["1/2","1/2","1/2"],"n":["EKMBA8Q1uP3WshghLR_r6MjYwVEids8y'
                                     b'Kb_03w8FOOFO","EHV8V6dj_VXvXZFUwMTT4yUy40kw5uYMXnFxoh_KZmos","EMUrvGYprwKm77'
                                     b'Oju22TlcoAEhL9QnnYfOBFPO1IyJUn"],"bt":"0","b":[],"c":[],"a":[]}')
        (seqner, saider) = hby1.db.gpse.getLast(keys=(ghab.pre,))  # Escrowed the event for sigs
        assert seqner.sn == 0
        assert saider.qb64 == "ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS"

        # Sith 2 so create second signature to get past the first escrow
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        evt = grouping.getEscrowedEvent(hab2.db, ghab2.pre, 0)
        assert evt == (b'{"v":"KERI10JSON000207_","t":"icp","d":"ENuUR3YvSR2-dFoN1zBN2p8W'
                       b'9BvsySnrY6g2vDS1EVAS","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"0","kt":["1/2","1/2","1/2"],"k":["DEXdkHRR2Nspj5cz'
                       b'sFvKOa-ZnGzMMFG5MLaBle19aJ9j","DL4SFzA89ls_auIqISf4UbSQGxNPc9y8Z'
                       b'2UrPDZupEsM","DERxxjBQUD4nGiaioBlqg8qpkRjJLGMe67OPdVsHFarQ"],"nt'
                       b'":["1/2","1/2","1/2"],"n":["EKMBA8Q1uP3WshghLR_r6MjYwVEids8yKb_0'
                       b'3w8FOOFO","EHV8V6dj_VXvXZFUwMTT4yUy40kw5uYMXnFxoh_KZmos","EMUrvG'
                       b'YprwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJUn"],"bt":"0","b":[],"c":[],'
                       b'"a":[]}-AABABBkMCMWP1Z2MMd6dBPlogRd1k6mv1joiHIyb8mXvp0H4kY0DHIPM'
                       b'9O6udZ1Bbyf3klr4uGnLs07qcCcnKGI6GsH')

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 to process all sigs together

        counselor.processEscrows()
        val = hby1.db.gpse.getLast(keys=(ghab.pre,))  # thold met, partial sig escrow should be empty
        assert val is None
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)
        counselor.postman.evts.popleft()

        # First Partial Rotation
        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None  # need to fix
        counselor.rotate(ghab=ghab, smids=smids, rmids=rmids, toad=0, cuts=list(), adds=list())
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.smids == smids
        assert rec.nsith == None
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
        assert saider.qb64b == b'EEXgdTuVXx6xxNc6g3y3Vql2Ocf4DW6quwgfh1iAia1e'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (b'{"v":"KERI10JSON000207_","t":"rot","d":"EEXgdTuVXx6xxNc6g3y3Vql2Ocf4DW6quwgf'
                              b'h1iAia1e","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"1","p":"EN'
                              b'uUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","kt":["1/2","1/2"],"k":["DEbwF93'
                              b'4m5TjdQbC18jSmk2CcPO7xzAemzePy4LKnA_U","DBL_WnUsuY-CbIFNkME8dYG0lMSNtT993IWc'
                              b'msPoUuED"],"nt":["1/2","1/2","1/2"],"n":["EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ0'
                              b'8zMICPhPTw","EGyO8jUZpLIlACoeLmfUzvE3mnxmcU2m_nyKfSDfpxV4","EMUrvGYprwKm77Oj'
                              b'u22TlcoAEhL9QnnYfOBFPO1IyJUn"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = coring.Serder(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON000207_","t":"rot","d":"EEXgdTuVXx6xxNc6g3y3Vql2'
                       b'Ocf4DW6quwgfh1iAia1e","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"1","p":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EV'
                       b'AS","kt":["1/2","1/2"],"k":["DEbwF934m5TjdQbC18jSmk2CcPO7xzAemze'
                       b'Py4LKnA_U","DBL_WnUsuY-CbIFNkME8dYG0lMSNtT993IWcmsPoUuED"],"nt":'
                       b'["1/2","1/2","1/2"],"n":["EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ08zMI'
                       b'CPhPTw","EGyO8jUZpLIlACoeLmfUzvE3mnxmcU2m_nyKfSDfpxV4","EMUrvGYp'
                       b'rwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJUn"],"bt":"0","br":[],"ba":[],'
                       b'"a":[]}-AABABDluTcoHbY-lxoCVAFS7wIyhJ5Wy4I7v1GRtO1vFnA4Q-du9z9LZ'
                       b'JDRRzWYmO9N4J_kpOFNqgJ5UECmmiz6qP0H')

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

        counselor.postman.evts.clear()  # Clear out postman for next rotation

        # Second Partial Rotation
        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None  # need to fix
        counselor.rotate(ghab=ghab, smids=smids, rmids=rmids, toad=0, cuts=list(), adds=list())
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.smids == smids
        assert rec.nsith == None
        assert rec.toad == 0

        counselor.processEscrows()  # process escrows to get witness-less event to next step
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is None
        assert len(counselor.postman.evts) == 2
        evt = counselor.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab2.pre
        assert evt["topic"] == "multisig"
        assert evt["serder"].raw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EPX4RtZs7_HHlxYqV5nXC2odIvMEJJpR_BDk'
                                     b'KZs2GnkR","i":"EOzS8kvK5AM0O9Qwub8wDVAmuetGCtUYVOQC6vpqbLQa","s":"2","p":"EE'
                                     b'X9vGqk8FJbe-pSusdW-t6dtTyPeOgtR8Cdhue6LgY7","kt":"1","k":["DK-j3FspSlqvjM0v9'
                                     b'nRUbgog54vminulol46VO1dDSAP"],"nt":"1","n":["EHMdUV5PuMt37ooqo1nW5DXkYC_lQXj'
                                     b'qgXY4V7GaWrAJ"],"bt":"0","br":[],"ba":[],"a":[]}')
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.smids == smids

        # rotate second identifiter in group, process escrows to generate group rotation event.
        hab2.rotate()
        rot = hab2.makeOwnEvent(sn=2)
        parsing.Parser().parse(ims=bytearray(rot), kvy=kev1)  # parse rotation
        counselor.processEscrows()  # second identifier has rotated, second stage clear
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is None

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 2
        assert saider.qb64b == b'EL8zEo0h9y6ZxAPI9wpJJnJQKgOQlJH69otwD6BhyLH7'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (b'{"v":"KERI10JSON000207_","t":"rot","d":"EL8zEo0h9y6ZxAPI9wpJJnJQKgOQlJH69otw'
                              b'D6BhyLH7","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"2","p":"EE'
                              b'XgdTuVXx6xxNc6g3y3Vql2Ocf4DW6quwgfh1iAia1e","kt":["1/2","1/2"],"k":["DK-j3Fs'
                              b'pSlqvjM0v9nRUbgog54vminulol46VO1dDSAP","DPkCnS9Z62sYgHuZSZH8whM0CiwZFdwLIAX-'
                              b'pfrbntdi"],"nt":["1/2","1/2","1/2"],"n":["EHMdUV5PuMt37ooqo1nW5DXkYC_lQXjqgX'
                              b'Y4V7GaWrAJ","EPbvHZm-pvhTH4KrWvInrg8gW3KbcYKiGceWFtwDfxmV","EMUrvGYprwKm77Oj'
                              b'u22TlcoAEhL9QnnYfOBFPO1IyJUn"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = coring.Serder(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON000207_","t":"rot","d":"EL8zEo0h9y6ZxAPI9wpJJnJQ'
                       b'KgOQlJH69otwD6BhyLH7","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"2","p":"EEXgdTuVXx6xxNc6g3y3Vql2Ocf4DW6quwgfh1iAia'
                       b'1e","kt":["1/2","1/2"],"k":["DK-j3FspSlqvjM0v9nRUbgog54vminulol4'
                       b'6VO1dDSAP","DPkCnS9Z62sYgHuZSZH8whM0CiwZFdwLIAX-pfrbntdi"],"nt":'
                       b'["1/2","1/2","1/2"],"n":["EHMdUV5PuMt37ooqo1nW5DXkYC_lQXjqgXY4V7'
                       b'GaWrAJ","EPbvHZm-pvhTH4KrWvInrg8gW3KbcYKiGceWFtwDfxmV","EMUrvGYp'
                       b'rwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJUn"],"bt":"0","br":[],"ba":[],'
                       b'"a":[]}-AABABDRZxyCUi78dR6qVLVVFvTJPNFt5Xc5uMzmmBKwI3MR5ntqACPce'
                       b'Svuy8o_rtWT9wLMAm9AkKM52VJF83bMgikE')

        # Create group rotation from second participant

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)

        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64]
        ndigs = [hab1.kever.nexter.digs[0], hab2.kever.nexter.digs[0], hab3.kever.nexter.digs[0]]
        assert ghab.kever.sn == 2
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert ghab.kever.nexter.digs == ndigs

        counselor.postman.evts.clear()  # Clear out postman for next rotation

        # Third Partial Rotation with Recovery
        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None  # need to fix
        counselor.rotate(ghab=ghab, smids=smids, rmids=rmids, toad=0, cuts=list(), adds=list())
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.smids == smids
        assert rec.nsith == None
        assert rec.toad == 0

        counselor.processEscrows()  # process escrows to get witness-less event to next step
        rec = hby1.db.glwe.get(keys=(ghab.pre,))
        assert rec is None
        assert len(counselor.postman.evts) == 2
        evt = counselor.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab2.pre
        assert evt["topic"] == "multisig"
        assert evt["serder"].raw == (b'{"v":"KERI10JSON000160_","t":"rot","d":"EAgOz6WCuULYu0JKkLIZvFqy8NWEiSgy0jwL'
                                     b'KpVKo3BH","i":"EOzS8kvK5AM0O9Qwub8wDVAmuetGCtUYVOQC6vpqbLQa","s":"3","p":"EP'
                                     b'X4RtZs7_HHlxYqV5nXC2odIvMEJJpR_BDkKZs2GnkR","kt":"1","k":["DE_7Y-c-xZXLb7Tcl'
                                     b'Inn6Q6hRbiYuaTTDqZGmBNjvVXA"],"nt":"1","n":["ELyh1BXGM7C0jfx3x-k8f1GLx9mIRHz'
                                     b'Fq3tiZgc9N5Vm"],"bt":"0","br":[],"ba":[],"a":[]}')
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is not None
        assert rec.smids == smids

        # rotate second identifiter in group, process escrows to generate group rotation event.
        hab3.rotate()
        rot = hab3.makeOwnEvent(sn=1)
        parsing.Parser().parse(ims=bytearray(rot), kvy=kev1)  # parse rotation
        counselor.processEscrows()  # second identifier has rotated, second stage clear
        rec = hby1.db.gpae.get(keys=(ghab.pre,))
        assert rec is None

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 3
        assert saider.qb64b == b'ECLqqyDAeqATdON4m8AapJc6XvQIuU9A5j1-gnDuzNc5'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (b'{"v":"KERI10JSON000207_","t":"rot","d":"ECLqqyDAeqATdON4m8AapJc6XvQIuU9A5j1-'
                              b'gnDuzNc5","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"3","p":"EL'
                              b'8zEo0h9y6ZxAPI9wpJJnJQKgOQlJH69otwD6BhyLH7","kt":["1/2","1/2"],"k":["DE_7Y-c'
                              b'-xZXLb7TclInn6Q6hRbiYuaTTDqZGmBNjvVXA","DDnDI3TRcmH_qzFOS3waORkqRcoydAWOboZq'
                              b'0gvermHM"],"nt":["1/2","1/2","1/2"],"n":["ELyh1BXGM7C0jfx3x-k8f1GLx9mIRHzFq3'
                              b'tiZgc9N5Vm","EPbvHZm-pvhTH4KrWvInrg8gW3KbcYKiGceWFtwDfxmV","EH0h1byPWpTfiMUc'
                              b'nk_nbeS4HEfnS_j0q2TAJAeIkFlu"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = coring.Serder(raw=bytes(evt))
        sigers = hab3.mgr.sign(serder.raw, verfers=hab3.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON000207_","t":"rot","d":"ECLqqyDAeqATdON4m8AapJc6'
                       b'XvQIuU9A5j1-gnDuzNc5","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"3","p":"EL8zEo0h9y6ZxAPI9wpJJnJQKgOQlJH69otwD6BhyL'
                       b'H7","kt":["1/2","1/2"],"k":["DE_7Y-c-xZXLb7TclInn6Q6hRbiYuaTTDqZ'
                       b'GmBNjvVXA","DDnDI3TRcmH_qzFOS3waORkqRcoydAWOboZq0gvermHM"],"nt":'
                       b'["1/2","1/2","1/2"],"n":["ELyh1BXGM7C0jfx3x-k8f1GLx9mIRHzFq3tiZg'
                       b'c9N5Vm","EPbvHZm-pvhTH4KrWvInrg8gW3KbcYKiGceWFtwDfxmV","EH0h1byP'
                       b'WpTfiMUcnk_nbeS4HEfnS_j0q2TAJAeIkFlu"],"bt":"0","br":[],"ba":[],'
                       b'"a":[]}-AABABDx3BuR3TuosKtRYfMjJgphpxISET6DTB3Iec9JJRewt7_WixffS'
                       b'ClsyD2RBLiNzt9ud37UNQrI3WDXlXU4EBYG')

        # Create group rotation from second participant

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)



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
