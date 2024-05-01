# -*- encoding: utf-8 -*-
"""
tests.app.grouping module

"""
from contextlib import contextmanager


from keri.app import habbing, grouping, notifying
from keri.core import coring, eventing, parsing, serdering
from keri.vdr import eventing as veventing
from keri.db import dbing
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
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2, local=True)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3, local=True)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1, local=True)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3, local=True)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1, local=True)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2, local=True)

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
                        ghab=ghab)
        (seqner, saider) = hby1.db.gpse.getLast(keys=(ghab.pre,))  # Escrowed the event for sigs
        assert seqner.sn == 0
        assert saider.qb64 == "ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS"

        # Sith 2 so create second signature to get past the first escrow
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab2.makeOwnInception(allowPartiallySigned=True)
        assert evt == (b'{"v":"KERI10JSON000207_","t":"icp","d":"ENuUR3YvSR2-dFoN1zBN2p8W'
                       b'9BvsySnrY6g2vDS1EVAS","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"0","kt":["1/2","1/2","1/2"],"k":["DEXdkHRR2Nspj5cz'
                       b'sFvKOa-ZnGzMMFG5MLaBle19aJ9j","DL4SFzA89ls_auIqISf4UbSQGxNPc9y8Z'
                       b'2UrPDZupEsM","DERxxjBQUD4nGiaioBlqg8qpkRjJLGMe67OPdVsHFarQ"],"nt'
                       b'":["1/2","1/2","1/2"],"n":["EKMBA8Q1uP3WshghLR_r6MjYwVEids8yKb_0'
                       b'3w8FOOFO","EHV8V6dj_VXvXZFUwMTT4yUy40kw5uYMXnFxoh_KZmos","EMUrvG'
                       b'YprwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJUn"],"bt":"0","b":[],"c":[],'
                       b'"a":[]}-AABBBBkMCMWP1Z2MMd6dBPlogRd1k6mv1joiHIyb8mXvp0H4kY0DHIPM'
                       b'9O6udZ1Bbyf3klr4uGnLs07qcCcnKGI6GsH')

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 to process all sigs together

        counselor.processEscrows()
        val = hby1.db.gpse.getLast(keys=(ghab.pre,))  # thold met, partial sig escrow should be empty
        assert val is None
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)

        # First Partial Rotation
        hab1.rotate()
        hab2.rotate()
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0]]
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith="2", nsith="2", toad=0, cuts=list(), adds=list(), verfers=merfers, digers=migers)
        rserder = serdering.SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 1
        assert saider.qb64b == b'EFWaDXMVIhIMpsXMOcnXhU0tkJfD_rPULkQzphoM_EVb'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (b'{"v":"KERI10JSON0001be_","t":"rot","d":"EFWaDXMVIhIMpsXMOcnXhU0tkJfD_rPULkQz'
                              b'phoM_EVb","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"1","p":"EN'
                              b'uUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","kt":"2","k":["DEbwF934m5TjdQbC1'
                              b'8jSmk2CcPO7xzAemzePy4LKnA_U","DBL_WnUsuY-CbIFNkME8dYG0lMSNtT993IWcmsPoUuED"]'
                              b',"nt":"2","n":["EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ08zMICPhPTw","EGyO8jUZpLIlA'
                              b'CoeLmfUzvE3mnxmcU2m_nyKfSDfpxV4"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = serdering.SerderKERI(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1], ondices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON0001be_","t":"rot","d":"EFWaDXMVIhIMpsXMOcnXhU0t'
                       b'kJfD_rPULkQzphoM_EVb","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"1","p":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EV'
                       b'AS","kt":"2","k":["DEbwF934m5TjdQbC18jSmk2CcPO7xzAemzePy4LKnA_U"'
                       b',"DBL_WnUsuY-CbIFNkME8dYG0lMSNtT993IWcmsPoUuED"],"nt":"2","n":["'
                       b'EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ08zMICPhPTw","EGyO8jUZpLIlACoeL'
                       b'mfUzvE3mnxmcU2m_nyKfSDfpxV4"],"bt":"0","br":[],"ba":[],"a":[]}-A'
                       b'ABABBIyjNbfOMPWr6Klz_mr3tqwZd-PYHxPwueh9lO68175xlaq9p6bo17f5D064'
                       b'JN3IvgWjXhB8B4T7y3bvrKodQF')

        # Create group rotation from second participant

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)

        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64]
        ndigs = [hab1.kever.ndigers[0].qb64, hab2.kever.ndigers[0].qb64]
        assert ghab.kever.sn == 1
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab.kever.ndigers] == ndigs

        # Second Partial Rotation

        hab1.rotate()
        hab2.rotate()
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0], hab3.kever.ndigers[0]]
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith="2", nsith="2", toad=0, cuts=list(), adds=list(), verfers=merfers, digers=migers)
        rserder = serdering.SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 2
        assert saider.qb64b == b'EAFmW50FmBfJXp4sPnYBp51L-aT9RESXYh8jylx2dEGc'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (b'{"v":"KERI10JSON0001ed_","t":"rot","d":"EAFmW50FmBfJXp4sPnYBp51L-aT9RESXYh8j'
                              b'ylx2dEGc","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"2","p":"EF'
                              b'WaDXMVIhIMpsXMOcnXhU0tkJfD_rPULkQzphoM_EVb","kt":"2","k":["DK-j3FspSlqvjM0v9'
                              b'nRUbgog54vminulol46VO1dDSAP","DPkCnS9Z62sYgHuZSZH8whM0CiwZFdwLIAX-pfrbntdi"]'
                              b',"nt":"2","n":["EHMdUV5PuMt37ooqo1nW5DXkYC_lQXjqgXY4V7GaWrAJ","EPbvHZm-pvhTH'
                              b'4KrWvInrg8gW3KbcYKiGceWFtwDfxmV","EMUrvGYprwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJ'
                              b'Un"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = serdering.SerderKERI(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON0001ed_","t":"rot","d":"EAFmW50FmBfJXp4sPnYBp51L'
                       b'-aT9RESXYh8jylx2dEGc","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"2","p":"EFWaDXMVIhIMpsXMOcnXhU0tkJfD_rPULkQzphoM_E'
                       b'Vb","kt":"2","k":["DK-j3FspSlqvjM0v9nRUbgog54vminulol46VO1dDSAP"'
                       b',"DPkCnS9Z62sYgHuZSZH8whM0CiwZFdwLIAX-pfrbntdi"],"nt":"2","n":["'
                       b'EHMdUV5PuMt37ooqo1nW5DXkYC_lQXjqgXY4V7GaWrAJ","EPbvHZm-pvhTH4KrW'
                       b'vInrg8gW3KbcYKiGceWFtwDfxmV","EMUrvGYprwKm77Oju22TlcoAEhL9QnnYfO'
                       b'BFPO1IyJUn"],"bt":"0","br":[],"ba":[],"a":[]}-AABABB4LwIPSggvF_E'
                       b'NzgPjNGb7L6jeFWgVEmy4AtBcK0pPzU6KGNvL2w1EciDE3OIdfeFa0ruuvxOhEAW'
                       b'ZtrvzYswD')

        # Create group rotation from second participant

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)

        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64]
        ndigs = [hab1.kever.ndigers[0].qb64, hab2.kever.ndigers[0].qb64, hab3.kever.ndigers[0].qb64]
        assert ghab.kever.sn == 2
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab.kever.ndigers] == ndigs

        # Third Partial Rotation with Recovery
        hab1.rotate()
        hab3.rotate()
        merfers = [hab1.kever.verfers[0], hab3.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab3.kever.ndigers[0]]
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith="2", nsith="2", toad=0, cuts=list(), adds=list(), verfers=merfers, digers=migers)
        rserder = serdering.SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 3
        assert saider.qb64b == b'EEQVk2x7-t_fnYNoOzeZppvIKkEbVRDDVf1oxGj_hnXw'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)
        assert bytes(evt) == (b'{"v":"KERI10JSON0001be_","t":"rot","d":"EEQVk2x7-t_fnYNoOzeZppvIKkEbVRDDVf1o'
                              b'xGj_hnXw","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"3","p":"EA'
                              b'FmW50FmBfJXp4sPnYBp51L-aT9RESXYh8jylx2dEGc","kt":"2","k":["DE_7Y-c-xZXLb7Tcl'
                              b'Inn6Q6hRbiYuaTTDqZGmBNjvVXA","DDnDI3TRcmH_qzFOS3waORkqRcoydAWOboZq0gvermHM"]'
                              b',"nt":"2","n":["ELyh1BXGM7C0jfx3x-k8f1GLx9mIRHzFq3tiZgc9N5Vm","EH0h1byPWpTfi'
                              b'MUcnk_nbeS4HEfnS_j0q2TAJAeIkFlu"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = serdering.SerderKERI(raw=bytes(evt))
        sigers = hab3.mgr.sign(serder.raw, verfers=hab3.kever.verfers, indexed=True, indices=[1], ondices=[2])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg == (b'{"v":"KERI10JSON0001be_","t":"rot","d":"EEQVk2x7-t_fnYNoOzeZppvI'
                       b'KkEbVRDDVf1oxGj_hnXw","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2v'
                       b'DS1EVAS","s":"3","p":"EAFmW50FmBfJXp4sPnYBp51L-aT9RESXYh8jylx2dE'
                       b'Gc","kt":"2","k":["DE_7Y-c-xZXLb7TclInn6Q6hRbiYuaTTDqZGmBNjvVXA"'
                       b',"DDnDI3TRcmH_qzFOS3waORkqRcoydAWOboZq0gvermHM"],"nt":"2","n":["'
                       b'ELyh1BXGM7C0jfx3x-k8f1GLx9mIRHzFq3tiZgc9N5Vm","EH0h1byPWpTfiMUcn'
                       b'k_nbeS4HEfnS_j0q2TAJAeIkFlu"],"bt":"0","br":[],"ba":[],"a":[]}-A'
                       b'AB2AABACB5hx8m8D908jtNsipRU3L-e2SYnR-2jihXLv-v2G_Z7cfJYJZPUfXNl8'
                       b'qvOQQdD-oyXQaTgU0kuJQbARZ3nWAD')

        # Create group rotation from second participant

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)


def test_the_seven():
    salt = b'0123456789abcdef'
    prefix = "counselor"
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True) as (hby3, hab3), \
            habbing.openHab(name=f"{prefix}_4", salt=salt, transferable=True) as (hby4, hab4), \
            habbing.openHab(name=f"{prefix}_5", salt=salt, transferable=True) as (hby5, hab5), \
            habbing.openHab(name=f"{prefix}_6", salt=salt, transferable=True) as (hby6, hab6), \
            habbing.openHab(name=f"{prefix}_7", salt=salt, transferable=True) as (hby7, hab7):
        counselor = grouping.Counselor(hby=hby1)

        # All the Habs, this will come in handy later
        # Keverys so we can process each other's inception messages.
        kev1 = eventing.Kevery(db=hab1.db)
        kev2 = eventing.Kevery(db=hab2.db)
        kev3 = eventing.Kevery(db=hab3.db)
        kev4 = eventing.Kevery(db=hab4.db)
        kev5 = eventing.Kevery(db=hab5.db)
        kev6 = eventing.Kevery(db=hab6.db)
        kev7 = eventing.Kevery(db=hab7.db)
        kevs = [kev1, kev2, kev3, kev4, kev5, kev6, kev7]

        icps = [hab1.makeOwnEvent(sn=0),
                hab2.makeOwnEvent(sn=0),
                hab3.makeOwnEvent(sn=0),
                hab4.makeOwnEvent(sn=0),
                hab5.makeOwnEvent(sn=0),
                hab6.makeOwnEvent(sn=0),
                hab7.makeOwnEvent(sn=0)
                ]

        # Introduce everyone to each other by parsing each others ICP event into our keverys
        for (kev, icp) in [(kev, icp) for (kdx, kev) in enumerate(kevs) for (idx, icp) in enumerate(icps) if
                           kdx != idx]:
            parsing.Parser().parse(ims=bytearray(icp), kvy=kev, local=True)

        smids = [hab1.pre, hab2.pre, hab3.pre, hab4.pre, hab5.pre, hab6.pre, hab7.pre]
        rmids = None  # need to fixe this
        inits = dict(isith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                     nsith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                     toad=0, wits=[])

        # Create group hab with init params
        ghab = hby1.makeGroupHab(group=f"{prefix}_group1", mhab=hab1,
                                 smids=smids, rmids=rmids, **inits)
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=prefixer.qb64)

        # Send to Counselor to post process through escrows
        counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=ghab)
        raw = (b'{"v":"KERI10JSON0003af_","t":"icp","d":"EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z'
               b'8gRdICIU","i":"EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU","s":"0","kt":["'
               b'1/3","1/3","1/3","1/3","1/3","1/3","1/3"],"k":["DEXdkHRR2Nspj5czsFvKOa-ZnGzM'
               b'MFG5MLaBle19aJ9j","DL4SFzA89ls_auIqISf4UbSQGxNPc9y8Z2UrPDZupEsM","DERxxjBQUD'
               b'4nGiaioBlqg8qpkRjJLGMe67OPdVsHFarQ","DP2tpU6FcZaHIjfVON5Ay6aIeyBVj6s3sZu21gn'
               b'1RPg5","DLtaCISrqMAED7fdhMalEk0Nx4UX8l8dQXtf_oZUl2pv","DNgs0Ut5IioeG_7P69G9L'
               b'VAJoiKGz3j0cfecXidh3USH","DDqo5hxM_OmAAq_4f90ydKwX4rj-IEgZjw-aaexBoooH"],"nt'
               b'":["1/3","1/3","1/3","1/3","1/3","1/3","1/3"],"n":["EKMBA8Q1uP3WshghLR_r6MjY'
               b'wVEids8yKb_03w8FOOFO","EHV8V6dj_VXvXZFUwMTT4yUy40kw5uYMXnFxoh_KZmos","EMUrvG'
               b'YprwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJUn","EHgm8iOfF9_67XjWB2JRBugrvy6D-lQmF9n'
               b'IWGHla17X","EHsPjPxkY00PW0IG3n834sBYqaLGWat9KKh-7qNSvH5O","EF9BqvXiUmAMpLVtx'
               b'CQ0m9BD3kwlzM6hx-jrI1CAt96R","EOKRgzqsueblcnkIrJhInqlpOwq8BVZCfJ7jBJ88Rt2Q"]'
               b',"bt":"0","b":[],"c":[],"a":[]}')
        (seqner, saider) = hby1.db.gpse.getLast(keys=(ghab.pre,))  # Escrowed the event for sigs
        assert seqner.sn == 0
        assert saider.qb64 == "EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU"

        # Get participation from everyone on inception
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab2.makeOwnInception(allowPartiallySigned=True)
        serd = serdering.SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBBAD108k4sWtYRv8jQaRbzX6kDebjdzFNVCh3N9cOAJqXV5IzmKdi60Cr0Eu'
                                   b'MaACskw0FCi73V2VX8BgFlxO8VIK')
        assert serd.raw == raw
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab3 = hby3.makeGroupHab(group=f"{prefix}_group3", mhab=hab3,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab3.makeOwnInception(allowPartiallySigned=True)
        serd = serdering.SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBCD6V2UkAovhY07MrJUNb-ICddDoyLde9i0FWclxfs7jes01YUEihfgbGERF'
                                   b'dKDR4kSr4WF3AskrZOPvMuXipAgP')
        assert serd.raw == raw
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab4 = hby4.makeGroupHab(group=f"{prefix}_group4", mhab=hab4,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab4.makeOwnInception(allowPartiallySigned=True)
        serd = serdering.SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBDBCZuZSFWy0tFshGny1pTR47GphDljd0SShmGRpUSpBX_BeHB1tdIObizaA'
                                   b'4GMoOcZ2sOWIe6muJPF_RaoKedYE')
        assert serd.raw == raw
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab5 = hby5.makeGroupHab(group=f"{prefix}_group5", mhab=hab5,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab5.makeOwnInception(allowPartiallySigned=True)
        serd = serdering.SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBEBsR6_hPId3H8fFG8EfevQVji8MsLAC72MjkkRxJp3h9v1vyFS1hAGGGxno'
                                   b'F5xSHOnpBpPwjMJwOCurAa3VrNAD')
        assert serd.raw == raw
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab6 = hby6.makeGroupHab(group=f"{prefix}_group6", mhab=hab6,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab6.makeOwnInception(allowPartiallySigned=True)
        serd = serdering.SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBFCi5hK6Ax4aBNsdoUkh7Q_CcSWJfpwkeF68aCO34J3BDN7k483lOxiyj6pl'
                                   b'8TQIQ7VJLBkoRscUMi_mls9jbpcD')
        assert serd.raw == raw
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab7 = hby7.makeGroupHab(group=f"{prefix}_group7", mhab=hab7,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab7.makeOwnInception(allowPartiallySigned=True)
        serd = serdering.SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBGCtPvRj00vEfT5Po6eH50DWfBWwAcQgvBaJ7LlYT7kQswkl_r-K9Lsxi5tm'
                                   b'Pvsb2xFtcMJkFf-BxamGhFo9OOcD')
        assert serd.raw == raw
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        kev1.processEscrows()  # Run escrows for Kevery1 to process all sigs together

        counselor.processEscrows()
        val = hby1.db.gpse.getLast(keys=(ghab.pre,))  # thold met, partial sig escrow should be empty
        assert val is None
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)

        # First Partial Rotation
        hab1.rotate()
        hab2.rotate()
        hab3.rotate()
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0], hab3.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0], hab3.kever.ndigers[0], hab4.kever.ndigers[0],
                  hab5.kever.ndigers[0], hab6.kever.ndigers[0], hab7.kever.ndigers[0]]
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith='["1/3", "1/3", "1/3"]', nsith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                          toad=0, cuts=list(), adds=list(), verfers=merfers, digers=migers)
        rserder = serdering.SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 1
        assert saider.qb64b == b'EIr_IqnpArv44v0lBmv-yzFRXtiKYzN1tH7wLb6KGdsb'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)

        raw = (b'{"v":"KERI10JSON000310_","t":"rot","d":"EIr_IqnpArv44v0lBmv-yzFRXtiKYzN1tH7w'
               b'Lb6KGdsb","i":"EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU","s":"1","p":"EL'
               b'-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU","kt":["1/3","1/3","1/3"],"k":["D'
               b'EbwF934m5TjdQbC18jSmk2CcPO7xzAemzePy4LKnA_U","DBL_WnUsuY-CbIFNkME8dYG0lMSNtT'
               b'993IWcmsPoUuED","DDnDI3TRcmH_qzFOS3waORkqRcoydAWOboZq0gvermHM"],"nt":["1/3",'
               b'"1/3","1/3","1/3","1/3","1/3","1/3"],"n":["EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ'
               b'08zMICPhPTw","EGyO8jUZpLIlACoeLmfUzvE3mnxmcU2m_nyKfSDfpxV4","EH0h1byPWpTfiMU'
               b'cnk_nbeS4HEfnS_j0q2TAJAeIkFlu","EHgm8iOfF9_67XjWB2JRBugrvy6D-lQmF9nIWGHla17X'
               b'","EHsPjPxkY00PW0IG3n834sBYqaLGWat9KKh-7qNSvH5O","EF9BqvXiUmAMpLVtxCQ0m9BD3k'
               b'wlzM6hx-jrI1CAt96R","EOKRgzqsueblcnkIrJhInqlpOwq8BVZCfJ7jBJ88Rt2Q"],"bt":"0"'
               b',"br":[],"ba":[],"a":[]}')
        assert bytes(evt) == raw

        # Grab the group ROT event, sign with Hab2 and parse into Kev1
        serder = serdering.SerderKERI(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg[serder.size:] == (b'-AABABAzvHN7yC3581dp9DxFXrKuXGP_62r_pzNMXL20T6RaPQASXvnBn6sKJ78z'
                                     b'KM9o499Zaz76j940nBoMT-yb9i8N')
        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception

        # Now sign the group ROT with Hab3 and parse into Kev1.  This should commit the event
        sigers = hab3.mgr.sign(serder.raw, verfers=hab3.kever.verfers, indexed=True, indices=[2])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg[serder.size:] == (b'-AABACB6z6LrzBAgpnrCopgiGxuki3sE-KAfY8t_rFq-2dIcQxRF4iCqCYNPKM9D'
                                     b'NbZbA1WDaQ72enSsR2UWMftX2kYD')

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()  # Get the rest of the way through counselor.
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)
        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64, hab3.kever.verfers[0].qb64]
        ndigs = [hab1.kever.ndigers[0].qb64, hab2.kever.ndigers[0].qb64, hab3.kever.ndigers[0].qb64,
                 hab4.kever.ndigers[0].qb64, hab5.kever.ndigers[0].qb64, hab6.kever.ndigers[0].qb64,
                 hab7.kever.ndigers[0].qb64]
        assert ghab.kever.sn == 1
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab.kever.ndigers] == ndigs

        # Second Partial Rotation
        hab1.rotate()
        hab2.rotate()
        hab3.rotate()
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0], hab3.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0], hab3.kever.ndigers[0], hab4.kever.ndigers[0],
                  hab5.kever.ndigers[0], hab6.kever.ndigers[0], hab7.kever.ndigers[0]]
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith='["1/3", "1/3", "1/3"]', nsith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                          toad=0, cuts=list(), adds=list(), verfers=merfers, digers=migers)
        rserder = serdering.SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 2
        assert saider.qb64b == b'EHV57zdXq3lB3PZ4mmlOWt4SOOubIKDpcG5sSZh5jayZ'
        key = dbing.dgKey(ghab.pre, saider.qb64b)  # digest key
        evt = hby1.db.getEvt(key=key)

        raw = (b'{"v":"KERI10JSON000310_","t":"rot","d":"EHV57zdXq3lB3PZ4mmlOWt4SOOubIKDpcG5s'
               b'SZh5jayZ","i":"EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU","s":"2","p":"EI'
               b'r_IqnpArv44v0lBmv-yzFRXtiKYzN1tH7wLb6KGdsb","kt":["1/3","1/3","1/3"],"k":["D'
               b'K-j3FspSlqvjM0v9nRUbgog54vminulol46VO1dDSAP","DPkCnS9Z62sYgHuZSZH8whM0CiwZFd'
               b'wLIAX-pfrbntdi","DIpMgmIJWFg7NUbFjML947RkXEDFpY2eg30gSl57CvSt"],"nt":["1/3",'
               b'"1/3","1/3","1/3","1/3","1/3","1/3"],"n":["EHMdUV5PuMt37ooqo1nW5DXkYC_lQXjqg'
               b'XY4V7GaWrAJ","EPbvHZm-pvhTH4KrWvInrg8gW3KbcYKiGceWFtwDfxmV","EAzDrPNvr1S2IqV'
               b'u40Tf08O9BT3hKD19pQFGByATE7Xu","EHgm8iOfF9_67XjWB2JRBugrvy6D-lQmF9nIWGHla17X'
               b'","EHsPjPxkY00PW0IG3n834sBYqaLGWat9KKh-7qNSvH5O","EF9BqvXiUmAMpLVtxCQ0m9BD3k'
               b'wlzM6hx-jrI1CAt96R","EOKRgzqsueblcnkIrJhInqlpOwq8BVZCfJ7jBJ88Rt2Q"],"bt":"0"'
               b',"br":[],"ba":[],"a":[]}')

        assert bytes(evt) == raw

        # Grab the group ROT event, sign with Hab2 and parse into Kev1
        serder = serdering.SerderKERI(raw=bytes(evt))
        sigers = hab2.mgr.sign(serder.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg[serder.size:] == (b'-AABABC4sYnDXCpO87BMXO21ofqHZKntPSdEXlBPlq1H8NOHD3KV-GHGWrXyrElK'
                                     b'BkQNBbNr9_yg-nSnBq7N9rAxEFcK')
        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception

        # Now sign the group ROT with Hab3 and parse into Kev1.  This should commit the event
        sigers = hab3.mgr.sign(serder.raw, verfers=hab3.kever.verfers, indexed=True, indices=[2])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg[serder.size:] == (b'-AABACAXyUueUfXC-ccUxBZTgnyHTXOy1wUYgQrhlk8FMJGQPiaOOdAzhaW71JeF'
                                     b'0By8Se-tKKuPP1xG41DblgXIwNkE')

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()  # Get the rest of the way through counselor.
        assert counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)
        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64, hab3.kever.verfers[0].qb64]
        ndigs = [hab1.kever.ndigers[0].qb64, hab2.kever.ndigers[0].qb64, hab3.kever.ndigers[0].qb64,
                 hab4.kever.ndigers[0].qb64, hab5.kever.ndigers[0].qb64, hab6.kever.ndigers[0].qb64,
                 hab7.kever.ndigers[0].qb64]

        assert ghab.kever.sn == 2
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab.kever.ndigers] == ndigs

        # Third Partial Rotation with Recovery (using 4 members not involved in previous rotations)
        # First we have to do a replay of all multisig AID and member AID events and get members 4 - 7 up to date
        msgs = [hab1.replay(), hab2.replay(), hab3.replay(), ghab.replay()]
        kevs = [kev4, kev5, kev6, kev7]
        for (kev, msg) in [(kev, msg) for kev in kevs for msg in msgs]:
            parsing.Parser().parse(ims=bytearray(msg), kvy=kev, local=True)

        assert kev4.kevers[ghab.pre] is not None
        assert kev5.kevers[ghab.pre] is not None
        assert kev6.kevers[ghab.pre] is not None
        assert kev7.kevers[ghab.pre] is not None

        # Create a new counselor with #4
        counselor4 = grouping.Counselor(hby=hby4)

        hab4.rotate()
        hab5.rotate()
        hab6.rotate()
        merfers = [hab4.kever.verfers[0], hab5.kever.verfers[0], hab6.kever.verfers[0]]
        migers = [hab4.kever.ndigers[0], hab5.kever.ndigers[0], hab6.kever.ndigers[0]]
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=ghab.kever.sn + 1)
        rot = ghab4.rotate(isith='["1/3", "1/3", "1/3"]', nsith='["1/3", "1/3", "1/3"]',
                           toad=0, cuts=list(), adds=list(), verfers=merfers, digers=migers)
        rserder = serdering.SerderKERI(raw=rot)

        counselor4.start(ghab=ghab4, prefixer=prefixer, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

        # partially signed group rotation
        val = hby4.db.gpse.get(keys=(ghab4.pre,))
        (seqner, saider) = val[0]
        assert seqner.sn == 3
        assert saider.qb64b == b'EGt_CZZASnY_iyB14ZXGQ4MxMtcSVW5oMHAuLM8BnqxV'
        key = dbing.dgKey(ghab4.pre, saider.qb64b)  # digest key
        evt = hby4.db.getEvt(key=key)

        raw = (b'{"v":"KERI10JSON00023c_","t":"rot","d":"EGt_CZZASnY_iyB14ZXGQ4MxMtcSVW5oMHAu'
               b'LM8BnqxV","i":"EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU","s":"3","p":"EH'
               b'V57zdXq3lB3PZ4mmlOWt4SOOubIKDpcG5sSZh5jayZ","kt":["1/3","1/3","1/3"],"k":["D'
               b'OKBAV-_3Z63w7yGmzu6pZCdUlpnEytbnChUhiTZGLa_","DOKFe0a-q2yyi_Yyh9wxLsSnG9e3nx'
               b'vAXlgMaIFSo0YE","DKq5vZxsl7lCtFkuxSdfRRm-Edzdk_mRnh3xlVESXpck"],"nt":["1/3",'
               b'"1/3","1/3"],"n":["EGX_K2uTEU6NOXfNo0VfhYLMrqADYHOoNk7WtT1SXOo2","EFl4us5uR0'
               b'hCiYcW7YyOaSAo-7zp8x1uBVU2E_tmhEwj","EMyxeTiM_cH5IHUI6nummgHMeW-_1oKw7rvqlDd'
               b'gha9v"],"bt":"0","br":[],"ba":[],"a":[]}')
        assert bytes(evt) == raw

        # Grab the group ROT event, sign with Hab5 and parse into Kev4
        serder = serdering.SerderKERI(raw=bytes(evt))
        sigers = hab5.mgr.sign(serder.raw, verfers=hab5.kever.verfers, indexed=True, indices=[1], ondices=[4])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg[serder.size:] == (b'-AAB2AABAEDSs99oM-KOhJ8q3H8lqGqPE3EvZxCHvCjZFvWHLzhqm91YlcskGqvK'
                                     b'8DwCg9dj8wRZP54ienzD52EIKvJWWh4J')
        parsing.Parser().parse(ims=bytearray(msg), kvy=kev4, local=True)  # parse second signed group inception

        # Now sign the group ROT with Hab6 and parse into Kev4.  This should commit the event
        sigers = hab6.mgr.sign(serder.raw, verfers=hab6.kever.verfers, indexed=True, indices=[2], ondices=[5])
        msg = eventing.messagize(serder=serder, sigers=sigers)
        assert msg[serder.size:] == (b'-AAB2AACAFBNVTM0Gw4rSd-S5HQ_KpmBfDedi7XNvB24ijMjQaekIfKlcdguPS8p'
                                     b'ax9ht7EE3SiTj9fSO_3f4SVUfJMPmHIK')

        parsing.Parser().parse(ims=bytearray(msg), kvy=kev4, local=True)  # parse second signed group inception
        kev4.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor4.processEscrows()  # Get the rest of the way through counselor.
        assert counselor4.complete(prefixer=prefixer, seqner=seqner, saider=saider)

        # Validate successful partial rotation
        nkeys = [hab4.kever.verfers[0].qb64, hab5.kever.verfers[0].qb64, hab6.kever.verfers[0].qb64]
        ndigs = [hab4.kever.ndigers[0].qb64, hab5.kever.ndigers[0].qb64, hab6.kever.ndigers[0].qb64]
        assert ghab4.kever.sn == 3
        assert [verfer.qb64 for verfer in ghab4.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab4.kever.ndigers] == ndigs


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
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2, local=True)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3, local=True)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1, local=True)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3, local=True)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1, local=True)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2, local=True)

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
                                  smids=smids, rmids=rmids, **inits)
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

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3, local=True)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2, local=True)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1, local=True)

        assert ghab1.pre in kev1.kevers
        assert ghab1.pre in kev2.kevers
        assert ghab1.pre in kev3.kevers

        yield (hby1, ghab1), (hby2, ghab2), (hby3, ghab3)


def test_multisig_incept(mockHelpingNowUTC):
    with habbing.openHab(name="test", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        exn, atc = grouping.multisigInceptExn(hab=hab, smids=aids, rmids=aids,
                                              icp=hab.makeOwnEvent(sn=hab.kever.sn))

        assert exn.ked["r"] == '/multisig/icp'
        assert exn.saidb == b'EGDEBUZW--n-GqOOwRflzBeqoQsYWKMOQVU_1YglG-BL'
        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAA'
                       b'AAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAC84-o2'
                       b'HKwKxhL1ttzykB9zuFaGV6OpQ05b1ZJYAeBFrR7kVON1aNjpLgQCG_0bY4FUiP7F'
                       b'GTVDrBjuFhbeDKAH-LAa5AACAA-e-icp-AABAACihaKoLnoXxRoxGbFfOy67YSh6'
                       b'UxtgjT2oxupnLDz2FlhevGJKTMObbdex9f0Hqob6uTavSJvsXf5RzitskkkC')
        data = exn.ked["a"]
        assert data["smids"] == aids
        assert "icp" in exn.ked['e']


def test_multisig_rotate(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):
        rot = (b'{"v":"KERI10JSON00023c_","t":"rot","d":"EGt_CZZASnY_iyB14ZXGQ4MxMtcSVW5oMHAu'
               b'LM8BnqxV","i":"EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU","s":"3","p":"EH'
               b'V57zdXq3lB3PZ4mmlOWt4SOOubIKDpcG5sSZh5jayZ","kt":["1/3","1/3","1/3"],"k":["D'
               b'OKBAV-_3Z63w7yGmzu6pZCdUlpnEytbnChUhiTZGLa_","DOKFe0a-q2yyi_Yyh9wxLsSnG9e3nx'
               b'vAXlgMaIFSo0YE","DKq5vZxsl7lCtFkuxSdfRRm-Edzdk_mRnh3xlVESXpck"],"nt":["1/3",'
               b'"1/3","1/3"],"n":["EGX_K2uTEU6NOXfNo0VfhYLMrqADYHOoNk7WtT1SXOo2","EFl4us5uR0'
               b'hCiYcW7YyOaSAo-7zp8x1uBVU2E_tmhEwj","EMyxeTiM_cH5IHUI6nummgHMeW-_1oKw7rvqlDd'
               b'gha9v"],"bt":"0","br":[],"ba":[],"a":[]}')
        exn, atc = grouping.multisigRotateExn(ghab=ghab1, smids=ghab1.smids, rmids=ghab1.rmids, rot=rot)

        assert exn.ked["r"] == '/multisig/rot'
        assert exn.saidb == b'EAE5RLyDb_3W8fUOzDOHWwpMAvHePaz8Jpz1XWL0b0lQ'
        assert atc == (b'-FABEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkaba0AAAAAAAAAAAAAAA'
                       b'AAAAAAAAEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkaba-AABAACzqlzb'
                       b'yRO_M5Kp6nyN1K5JZ9s9D4UAreliSs4OiyCe_y9KnDeP65tub3DW5hUKlVQWnPv4'
                       b'TrOBHk2vJNOEJtAF')

        data = exn.ked["a"]
        assert data["smids"] == ghab1.smids
        assert data["gid"] == ghab1.pre
        assert "rot" in exn.ked["e"]


def test_multisig_interact(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):
        ixn = ghab1.mhab.interact()
        exn, atc = grouping.multisigInteractExn(ghab=ghab1, aids=ghab1.smids,
                                                ixn=ixn)

        assert exn.ked["r"] == '/multisig/ixn'
        assert exn.saidb == b'EGQ_DqGlSBx2MKJfHr6liXAngFpQ0UCtV1cdVMUtJHdN'
        assert atc == (b'-FABEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkaba0AAAAAAAAAAAAAAA'
                       b'AAAAAAAAEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkaba-AABAAB3yX6b'
                       b'EXb8N63PKaMaFqijZVT5TqVtoO8q1BFnoJW3rDkNuJ9lEMpEN-44HKGtvniWZ6-d'
                       b'CVPS4fsEXKZAKGkB-LAa5AACAA-e-ixn-AABAABG58m7gibjdrQ8YU-8WQ8A70nc'
                       b'tYekYr3xdfZ5WgDQOD0bb9pI7SuuaJvzfAQisLAYQnztA82pAo1Skhf1vQwD')
        data = exn.ked["a"]
        assert data["smids"] == ghab1.smids
        assert data["gid"] == ghab1.pre
        assert "ixn" in exn.ked["e"]


def test_multisig_registry_incept(mockHelpingNowUTC, mockCoringRandomNonce):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):
        vcp = veventing.incept(ghab1.pre)
        ixn = ghab1.mhab.interact(data=[dict(i=vcp.pre, s="0", d=vcp.said)])
        exn, atc = grouping.multisigRegistryInceptExn(ghab=ghab1, vcp=vcp.raw, anc=ixn,
                                                      usage="Issue vLEI Credentials")

        assert exn.ked["r"] == '/multisig/vcp'
        assert exn.saidb == b'EJN27EYqgxTS2NCHdnjE-CU0UikV5a1Cw5OZdv-g0jQ6'
        assert atc == (b'-FABEDEf72ZZ9mhpT1Xz-_YkXl7cg93sjZUFLIsxaFNTbXQO0AAAAAAAAAAAAAAA'
                       b'AAAAAAAAEDEf72ZZ9mhpT1Xz-_YkXl7cg93sjZUFLIsxaFNTbXQO-AABAABsPiWf'
                       b'UE9L7D9KBVOYMg1rt88gK9DBkiBYb21xMR0YH7sCT0hqwX9y8CM5Y6jQwzz3NqqN'
                       b'-aJWShzz1mbtb5AG-LAa5AACAA-e-anc-AABAABXlwkzbp_tC4MEbx1Uyny1o7dB'
                       b'GHrYjU3u90Mhv2GtrIGG-7va1jZnlXef2R_LM4TRN8_XjmpLv1skcJaM90UB')
        data = exn.ked["a"]
        assert data == {'gid': 'EEVG5a8c88Fg9vH-6zQP6gJdc4LxVbUTRydx-JhpDcob',
                        'usage': 'Issue vLEI Credentials'}
        assert "vcp" in exn.ked["e"]
        assert "anc" in exn.ked["e"]


def test_multisig_incept_handler(mockHelpingNowUTC):
    with habbing.openHab(name="test0", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        exn, atc = grouping.multisigInceptExn(hab=hab, smids=aids, rmids=aids,
                                              icp=hab.makeOwnEvent(sn=hab.kever.sn))

        notifier = notifying.Notifier(hby=hby)
        mux = grouping.Multiplexor(hby=hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        grouping.loadHandlers(exc=exc, mux=mux)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)
        assert len(notifier.signaler.signals) == 0

        esaid = exn.ked['e']['d']
        saiders = hby.db.meids.get(keys=(esaid, ))
        assert len(saiders) == 1
        assert saiders[0].qb64 == exn.said
        prefixers = hby.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 1
        assert prefixers[0].qb64 == exn.pre


def test_multisig_rotate_handler(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (hby2, ghab2), (_, _)):
        msg = ghab1.mhab.rotate()
        notifier = notifying.Notifier(hby=hby1)
        mux = grouping.Multiplexor(hby=hby1, notifier=notifier)
        exc = exchanging.Exchanger(hby=hby1, handlers=[])
        grouping.loadHandlers(exc=exc, mux=mux)

        # create and send message from ghab2
        exn, atc = grouping.multisigRotateExn(ghab=ghab2, smids=ghab1.smids, rmids=ghab1.rmids,
                                              rot=msg)
        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        # One notification
        assert len(notifier.signaler.signals) == 1

        esaid = exn.ked['e']['d']
        saiders = hby1.db.meids.get(keys=(esaid, ))
        assert len(saiders) == 1
        assert saiders[0].qb64 == exn.said
        prefixers = hby1.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 1
        assert prefixers[0].qb64 == ghab2.mhab.pre

        # Send the same message from ghab1
        exn, atc = grouping.multisigRotateExn(ghab=ghab1, smids=ghab1.smids, rmids=ghab1.rmids,
                                              rot=msg)
        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        # There should still only be one notification because we don't notify for our own event
        assert len(notifier.signaler.signals) == 1

        saiders = hby1.db.meids.get(keys=(esaid, ))
        assert len(saiders) == 2
        assert saiders[1].qb64 == exn.said
        prefixers = hby1.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 2
        assert prefixers[1].qb64 == ghab1.mhab.pre


def test_multisig_interact_handler(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, ghab2), (_, _)):
        ixn = ghab1.mhab.interact()
        exn, atc = grouping.multisigInteractExn(ghab=ghab2, aids=ghab1.smids,
                                                ixn=ixn)

        notifier = notifying.Notifier(hby=hby1)
        mux = grouping.Multiplexor(hby=hby1, notifier=notifier)
        exc = exchanging.Exchanger(hby=hby1, handlers=[])
        grouping.loadHandlers(exc=exc, mux=mux)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        esaid = exn.ked['e']['d']
        assert len(notifier.signaler.signals) == 1
        saiders = hby1.db.meids.get(keys=(esaid, ))
        assert len(saiders) == 1
        assert saiders[0].qb64 == exn.said
        prefixers = hby1.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 1
        assert prefixers[0].qb64 == ghab2.mhab.pre
