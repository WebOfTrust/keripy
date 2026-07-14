# -*- encoding: utf-8 -*-
"""
tests.app.grouping module

"""
from contextlib import contextmanager
from types import SimpleNamespace

from hio.base import doing

from keri.kering import Version, Vrsn_1_0, Vrsn_2_0, Kinds
from keri.app import (Notifier, Counselor, Multiplexor,
                      openHab, openCF, multisigInceptExn,
                      multisigRotateExn, multisigInteractExn,
                      multisigRegistryInceptExn)
from keri.app import grouping

from keri.app.grouping import loadHandlers

from keri.core import (Prefixer, Number, Diger, Kevery,
                       Parser, SerderKERI, Counter,
                       Codens, Kramer, messagize)

from keri.vdr.eventing import incept
from keri.peer import Exchanger

TEST_VERSION = Vrsn_1_0
KWA = dict(version=TEST_VERSION, kind=Kinds.json)


def test_counselor_explicit_version_propagates_to_default_anchorer_and_delegator_queries(monkeypatch):
    captures = {}

    class FakeAnchorer(doing.Doer):
        def __init__(self, hby, proxy=None, auths=None, version=None, kind=None, **kwa):
            super().__init__(**kwa)
            captures["anchorer_version"] = version
            captures["anchorer_kind"] = kind

        def delegation(self, pre, sn=None, proxy=None, auths=None):
            captures["delegation"] = dict(pre=pre, sn=sn, proxy=proxy, auths=auths)

        def complete(self, prefixer, number, diger=None):
            return False

    class FakeWitnessInquisitor(doing.Doer):
        def __init__(self, hby, *args, **kwa):
            super().__init__(**kwa)
            self.hby = hby

        def query(self, *args, **kwargs):
            captures["query_args"] = args
            captures["query_kwargs"] = kwargs

    class FakeReceiptor(doing.Doer):
        def __init__(self, hby, *args, **kwa):
            super().__init__(**kwa)
            self.hby = hby
            self.msgs = []
            self.gets = []
            self.cues = []

    class FakeTopItemStore:
        def __init__(self, items=None):
            self.items = list(items or [])
            self.removed = []
            self.added = []

        def getTopItemIter(self):
            return iter(self.items)

        def rem(self, keys):
            self.removed.append(keys)
            self.items = []

        def add(self, keys, val):
            self.added.append((keys, val))

    class FakeLastStore:
        def __init__(self, value):
            self.value = value

        def getLast(self, keys, on=None):
            return self.value

    class FakeSigsStore:
        def __init__(self, sigers):
            self.sigers = sigers

        def get(self, keys):
            return self.sigers

    monkeypatch.setattr(grouping, "Anchorer", FakeAnchorer)
    monkeypatch.setattr(grouping, "WitnessInquisitor", FakeWitnessInquisitor)
    monkeypatch.setattr(grouping, "Receiptor", FakeReceiptor)

    pre = "EGroupPrefix"
    delpre = "EDelegatorPrefix"
    number = Number(num=1)
    diger = SimpleNamespace(qb64="EGroupEventDigest")

    gpse = FakeTopItemStore([((pre,), (number, diger))])
    gdee = FakeTopItemStore()
    fake_db = SimpleNamespace(gpse=gpse,
                              gdee=gdee,
                              kels=FakeLastStore("abc"),
                              sigs=FakeSigsStore([SimpleNamespace(index=1)]))
    fake_ghab = SimpleNamespace(
        pre=pre,
        kever=SimpleNamespace(
            verfers=[SimpleNamespace(qb64="DFirst"), SimpleNamespace(qb64="DSecond")],
            delegated=True,
            ilk=grouping.Ilks.dip,
            delpre=delpre,
        ),
        mhab=SimpleNamespace(pre="ELocalMember",
                             kever=SimpleNamespace(verfers=[SimpleNamespace(qb64="DFirst")])),
    )
    fake_hby = SimpleNamespace(db=fake_db, habs={pre: fake_ghab})

    counselor = Counselor(hby=fake_hby, version=Vrsn_1_0, kind=Kinds.json)
    counselor.processPartialSignedEscrow()

    assert captures["anchorer_version"] == Vrsn_1_0
    assert captures["anchorer_kind"] == Kinds.json
    assert captures["query_kwargs"] == dict(
        src="ELocalMember",
        pre=delpre,
        anchor=dict(i=pre, s=number.snh, d=diger.qb64),
        version=Vrsn_1_0,
        gvrsn=Vrsn_1_0,
        kind=Kinds.json,
    )


def test_counselor():
    salt = b'0123456789abcdef'
    prefix = "counselor"
    with openHab(name=f"{prefix}_1", salt=salt, transferable=True, **KWA) as (hby1, hab1), \
            openHab(name=f"{prefix}_2", salt=salt, transferable=True, **KWA) as (hby2, hab2), \
            openHab(name=f"{prefix}_3", salt=salt, transferable=True, **KWA) as (hby3, hab3):
        counselor = Counselor(hby=hby1, version=TEST_VERSION, kind=Kinds.json)

        # Keverys so we can process each other's inception messages.
        kev1 = Kevery(db=hab1.db, lax=True, local=False)
        kev2 = Kevery(db=hab2.db, lax=True, local=False)
        kev3 = Kevery(db=hab3.db, lax=True, local=False)

        icp1 = hab1.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp1), kvy=kev2, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp1), kvy=kev3, local=True)
        icp2 = hab2.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp2), kvy=kev1, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp2), kvy=kev3, local=True)
        icp3 = hab3.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp3), kvy=kev1, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp3), kvy=kev2, local=True)

        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None  # need to fixe this
        inits = dict(isith='["1/2", "1/2", "1/2"]', nsith='["1/2", "1/2", "1/2"]',
                     toad=0, wits=[], **KWA)

        # Create group hab with init params
        ghab = hby1.makeGroupHab(group=f"{prefix}_group1", mhab=hab1,
                                 smids=smids, rmids=rmids, **inits)
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=0)
        diger = Diger(qb64=prefixer.qb64)

        # Send to Counselor to post process through escrows
        counselor.start(prefixer=prefixer, number=number, diger=diger,
                        ghab=ghab)
        (number, diger) = hby1.db.gpse.getLast(keys=(ghab.pre,))  # Escrowed the event for sigs
        assert number.sn == 0
        assert diger.qb64 == "ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS"

        # Sith 2 so create second signature to get past the first escrow
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab2.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=TEST_VERSION)
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

        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 to process all sigs together

        counselor.processEscrows()
        val = hby1.db.gpse.getLast(keys=(ghab.pre,))  # thold met, partial sig escrow should be empty
        assert val is None
        assert counselor.complete(prefixer=prefixer, number=number, diger=diger)

        # First Partial Rotation
        hab1.rotate(framed=True, gvrsn=TEST_VERSION, **KWA)
        hab2.rotate(framed=True, gvrsn=TEST_VERSION, **KWA)
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0]]
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith="2", nsith="2", toad=0, cuts=list(), adds=list(),
                          verfers=merfers, digers=migers, framed=True, gvrsn=TEST_VERSION, **KWA)
        rserder = SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, number=number, diger=Diger(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (number, diger) = val[0]
        assert number.sn == 1
        assert diger.qb64b == b'EFWaDXMVIhIMpsXMOcnXhU0tkJfD_rPULkQzphoM_EVb'
        srdr = hby1.db.evts.get(keys=(ghab.pre, diger.qb64b))
        assert srdr is not None and srdr.raw == (b'{"v":"KERI10JSON0001be_","t":"rot","d":"EFWaDXMVIhIMpsXMOcnXhU0tkJfD_rPULkQz'
                              b'phoM_EVb","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"1","p":"EN'
                              b'uUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","kt":"2","k":["DEbwF934m5TjdQbC1'
                              b'8jSmk2CcPO7xzAemzePy4LKnA_U","DBL_WnUsuY-CbIFNkME8dYG0lMSNtT993IWcmsPoUuED"]'
                              b',"nt":"2","n":["EBOgQ1MOWQ2eWIqDuqjinhh3L3O5qHPEZ08zMICPhPTw","EGyO8jUZpLIlA'
                              b'CoeLmfUzvE3mnxmcU2m_nyKfSDfpxV4"],"bt":"0","br":[],"ba":[],"a":[]}')

        sigers = hab2.mgr.sign(srdr.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1], ondices=[1])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
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

        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, number=number, diger=diger)

        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64]
        ndigs = [hab1.kever.ndigers[0].qb64, hab2.kever.ndigers[0].qb64]
        assert ghab.kever.sn == 1
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab.kever.ndigers] == ndigs

        # Second Partial Rotation

        hab1.rotate(framed=True, gvrsn=TEST_VERSION, **KWA)
        hab2.rotate(framed=True, gvrsn=TEST_VERSION, **KWA)
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0], hab3.kever.ndigers[0]]
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith="2", nsith="2", toad=0, cuts=list(), adds=list(),
                          verfers=merfers, digers=migers, framed=True, gvrsn=TEST_VERSION, **KWA)
        rserder = SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, number=number, diger=Diger(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (number, diger) = val[0]
        assert number.sn == 2
        assert diger.qb64b == b'EAFmW50FmBfJXp4sPnYBp51L-aT9RESXYh8jylx2dEGc'
        srdr = hby1.db.evts.get(keys=(ghab.pre, diger.qb64b))
        assert srdr is not None and srdr.raw == (b'{"v":"KERI10JSON0001ed_","t":"rot","d":"EAFmW50FmBfJXp4sPnYBp51L-aT9RESXYh8j'
                              b'ylx2dEGc","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"2","p":"EF'
                              b'WaDXMVIhIMpsXMOcnXhU0tkJfD_rPULkQzphoM_EVb","kt":"2","k":["DK-j3FspSlqvjM0v9'
                              b'nRUbgog54vminulol46VO1dDSAP","DPkCnS9Z62sYgHuZSZH8whM0CiwZFdwLIAX-pfrbntdi"]'
                              b',"nt":"2","n":["EHMdUV5PuMt37ooqo1nW5DXkYC_lQXjqgXY4V7GaWrAJ","EPbvHZm-pvhTH'
                              b'4KrWvInrg8gW3KbcYKiGceWFtwDfxmV","EMUrvGYprwKm77Oju22TlcoAEhL9QnnYfOBFPO1IyJ'
                              b'Un"],"bt":"0","br":[],"ba":[],"a":[]}')

        sigers = hab2.mgr.sign(srdr.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
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

        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, number=number, diger=diger)

        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64]
        ndigs = [hab1.kever.ndigers[0].qb64, hab2.kever.ndigers[0].qb64, hab3.kever.ndigers[0].qb64]
        assert ghab.kever.sn == 2
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab.kever.ndigers] == ndigs

        # Third Partial Rotation with Recovery
        hab1.rotate(framed=True, gvrsn=TEST_VERSION, **KWA)
        hab3.rotate(framed=True, gvrsn=TEST_VERSION, **KWA)
        merfers = [hab1.kever.verfers[0], hab3.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab3.kever.ndigers[0]]
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith="2", nsith="2", toad=0, cuts=list(), adds=list(),
                          verfers=merfers, digers=migers, framed=True, gvrsn=TEST_VERSION, **KWA)
        rserder = SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, number=number, diger=Diger(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (number, diger) = val[0]
        assert number.sn == 3
        assert diger.qb64b == b'EEQVk2x7-t_fnYNoOzeZppvIKkEbVRDDVf1oxGj_hnXw'
        evt = hby1.db.evts.get(keys=(ghab.pre, diger.qb64b))
        assert evt is not None and evt.raw == (b'{"v":"KERI10JSON0001be_","t":"rot","d":"EEQVk2x7-t_fnYNoOzeZppvIKkEbVRDDVf1o'
                              b'xGj_hnXw","i":"ENuUR3YvSR2-dFoN1zBN2p8W9BvsySnrY6g2vDS1EVAS","s":"3","p":"EA'
                              b'FmW50FmBfJXp4sPnYBp51L-aT9RESXYh8jylx2dEGc","kt":"2","k":["DE_7Y-c-xZXLb7Tcl'
                              b'Inn6Q6hRbiYuaTTDqZGmBNjvVXA","DDnDI3TRcmH_qzFOS3waORkqRcoydAWOboZq0gvermHM"]'
                              b',"nt":"2","n":["ELyh1BXGM7C0jfx3x-k8f1GLx9mIRHzFq3tiZgc9N5Vm","EH0h1byPWpTfi'
                              b'MUcnk_nbeS4HEfnS_j0q2TAJAeIkFlu"],"bt":"0","br":[],"ba":[],"a":[]}')

        serder = evt
        sigers = hab3.mgr.sign(serder.raw, verfers=hab3.kever.verfers, indexed=True, indices=[1], ondices=[2])
        msg = messagize(serder=serder, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
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

        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, number=number, diger=diger)


def test_the_seven():
    salt = b'0123456789abcdef'
    prefix = "counselor"
    with openHab(name=f"{prefix}_1", salt=salt, transferable=True, **KWA) as (hby1, hab1), \
            openHab(name=f"{prefix}_2", salt=salt, transferable=True, **KWA) as (hby2, hab2), \
            openHab(name=f"{prefix}_3", salt=salt, transferable=True, **KWA) as (hby3, hab3), \
            openHab(name=f"{prefix}_4", salt=salt, transferable=True, **KWA) as (hby4, hab4), \
            openHab(name=f"{prefix}_5", salt=salt, transferable=True, **KWA) as (hby5, hab5), \
            openHab(name=f"{prefix}_6", salt=salt, transferable=True, **KWA) as (hby6, hab6), \
            openHab(name=f"{prefix}_7", salt=salt, transferable=True, **KWA) as (hby7, hab7):
        counselor = Counselor(hby=hby1)

        # All the Habs, this will come in handy later
        # Keverys so we can process each other's inception messages.
        kev1 = Kevery(db=hab1.db)
        kev2 = Kevery(db=hab2.db)
        kev3 = Kevery(db=hab3.db)
        kev4 = Kevery(db=hab4.db)
        kev5 = Kevery(db=hab5.db)
        kev6 = Kevery(db=hab6.db)
        kev7 = Kevery(db=hab7.db)
        kevs = [kev1, kev2, kev3, kev4, kev5, kev6, kev7]

        icps = \
        [
            hab1.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION),
            hab2.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION),
            hab3.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION),
            hab4.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION),
            hab5.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION),
            hab6.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION),
            hab7.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        ]

        # Introduce everyone to each other by parsing each others ICP event into our keverys
        for (kev, icp) in [(kev, icp) for (kdx, kev) in enumerate(kevs) for (idx, icp) in enumerate(icps) if
                           kdx != idx]:
            Parser(version=TEST_VERSION).parse(ims=bytearray(icp), kvy=kev, local=True)

        smids = [hab1.pre, hab2.pre, hab3.pre, hab4.pre, hab5.pre, hab6.pre, hab7.pre]
        rmids = None  # need to fixe this
        inits = dict(isith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                     nsith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                     toad=0, wits=[], **KWA)

        # Create group hab with init params
        ghab = hby1.makeGroupHab(group=f"{prefix}_group1", mhab=hab1,
                                 smids=smids, rmids=rmids, **inits)
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=0)
        diger = Diger(qb64=prefixer.qb64)

        # Send to Counselor to post process through escrows
        counselor.start(prefixer=prefixer, number=number, diger=diger, ghab=ghab)
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
        (nunber, diger) = hby1.db.gpse.getLast(keys=(ghab.pre,))  # Escrowed the event for sigs
        assert nunber.sn == 0
        assert diger.qb64 == "EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU"

        # Get participation from everyone on inception
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab2.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=TEST_VERSION)
        serd = SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBBAD108k4sWtYRv8jQaRbzX6kDebjdzFNVCh3N9cOAJqXV5IzmKdi60Cr0Eu'
                                   b'MaACskw0FCi73V2VX8BgFlxO8VIK')
        assert serd.raw == raw
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab3 = hby3.makeGroupHab(group=f"{prefix}_group3", mhab=hab3,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab3.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=TEST_VERSION)
        serd = SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBCD6V2UkAovhY07MrJUNb-ICddDoyLde9i0FWclxfs7jes01YUEihfgbGERF'
                                   b'dKDR4kSr4WF3AskrZOPvMuXipAgP')
        assert serd.raw == raw
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab4 = hby4.makeGroupHab(group=f"{prefix}_group4", mhab=hab4,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab4.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=TEST_VERSION)
        serd = SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBDBCZuZSFWy0tFshGny1pTR47GphDljd0SShmGRpUSpBX_BeHB1tdIObizaA'
                                   b'4GMoOcZ2sOWIe6muJPF_RaoKedYE')
        assert serd.raw == raw
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab5 = hby5.makeGroupHab(group=f"{prefix}_group5", mhab=hab5,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab5.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=TEST_VERSION)
        serd = SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBEBsR6_hPId3H8fFG8EfevQVji8MsLAC72MjkkRxJp3h9v1vyFS1hAGGGxno'
                                   b'F5xSHOnpBpPwjMJwOCurAa3VrNAD')
        assert serd.raw == raw
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab6 = hby6.makeGroupHab(group=f"{prefix}_group6", mhab=hab6,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab6.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=TEST_VERSION)
        serd = SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBFCi5hK6Ax4aBNsdoUkh7Q_CcSWJfpwkeF68aCO34J3BDN7k483lOxiyj6pl'
                                   b'8TQIQ7VJLBkoRscUMi_mls9jbpcD')
        assert serd.raw == raw
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        ghab7 = hby7.makeGroupHab(group=f"{prefix}_group7", mhab=hab7,
                                  smids=smids, rmids=rmids, **inits)
        evt = ghab7.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=TEST_VERSION)
        serd = SerderKERI(raw=bytearray(evt))
        assert evt[serd.size:] == (b'-AABBGCtPvRj00vEfT5Po6eH50DWfBWwAcQgvBaJ7LlYT7kQswkl_r-K9Lsxi5tm'
                                   b'Pvsb2xFtcMJkFf-BxamGhFo9OOcD')
        assert serd.raw == raw
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)  # parse second signed group inception

        kev1.processEscrows()  # Run escrows for Kevery1 to process all sigs together

        counselor.processEscrows()
        val = hby1.db.gpse.getLast(keys=(ghab.pre,))  # thold met, partial sig escrow should be empty
        assert val is None
        assert counselor.complete(prefixer=prefixer, number=number, diger=diger)

        # First Partial Rotation
        hab1.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        hab2.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        hab3.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0], hab3.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0], hab3.kever.ndigers[0], hab4.kever.ndigers[0],
                  hab5.kever.ndigers[0], hab6.kever.ndigers[0], hab7.kever.ndigers[0]]
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith='["1/3", "1/3", "1/3"]', nsith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                          toad=0, cuts=list(), adds=list(), verfers=merfers,
                          digers=migers, framed=True, **KWA, gvrsn=TEST_VERSION)
        rserder = SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, number=number, diger=Diger(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (number, diger) = val[0]
        assert number.sn == 1
        assert diger.qb64b == b'EIr_IqnpArv44v0lBmv-yzFRXtiKYzN1tH7wLb6KGdsb'
        srdr = hby1.db.evts.get(keys=(ghab.pre, diger.qb64b))

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
        assert srdr is not None and srdr.raw == raw

        # Grab the group ROT event, sign with Hab2 and parse into Kev1
        sigers = hab2.mgr.sign(srdr.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
        assert msg[srdr.size:] == (b'-AABABAzvHN7yC3581dp9DxFXrKuXGP_62r_pzNMXL20T6RaPQASXvnBn6sKJ78z'
                                     b'KM9o499Zaz76j940nBoMT-yb9i8N')
        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception

        # Now sign the group ROT with Hab3 and parse into Kev1.  This should commit the event
        sigers = hab3.mgr.sign(srdr.raw, verfers=hab3.kever.verfers, indexed=True, indices=[2])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
        assert msg[srdr.size:] == (b'-AABACB6z6LrzBAgpnrCopgiGxuki3sE-KAfY8t_rFq-2dIcQxRF4iCqCYNPKM9D'
                                     b'NbZbA1WDaQ72enSsR2UWMftX2kYD')

        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()  # Get the rest of the way through counselor.
        assert counselor.complete(prefixer=prefixer, number=number, diger=diger)
        # Validate successful partial rotation
        nkeys = [hab1.kever.verfers[0].qb64, hab2.kever.verfers[0].qb64, hab3.kever.verfers[0].qb64]
        ndigs = [hab1.kever.ndigers[0].qb64, hab2.kever.ndigers[0].qb64, hab3.kever.ndigers[0].qb64,
                 hab4.kever.ndigers[0].qb64, hab5.kever.ndigers[0].qb64, hab6.kever.ndigers[0].qb64,
                 hab7.kever.ndigers[0].qb64]
        assert ghab.kever.sn == 1
        assert [verfer.qb64 for verfer in ghab.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab.kever.ndigers] == ndigs

        # Second Partial Rotation
        hab1.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        hab2.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        hab3.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0], hab3.kever.verfers[0]]
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0], hab3.kever.ndigers[0], hab4.kever.ndigers[0],
                  hab5.kever.ndigers[0], hab6.kever.ndigers[0], hab7.kever.ndigers[0]]
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=ghab.kever.sn + 1)
        rot = ghab.rotate(isith='["1/3", "1/3", "1/3"]', nsith='["1/3", "1/3", "1/3", "1/3", "1/3", "1/3", "1/3"]',
                          toad=0, cuts=list(), adds=list(), verfers=merfers,
                          digers=migers, framed=True, **KWA, gvrsn=TEST_VERSION)
        rserder = SerderKERI(raw=rot)

        counselor.start(ghab=ghab, prefixer=prefixer, number=number, diger=Diger(qb64=rserder.said))

        # partially signed group rotation
        val = hby1.db.gpse.get(keys=(ghab.pre,))
        (number, diger) = val[0]
        assert number.sn == 2
        assert diger.qb64b == b'EHV57zdXq3lB3PZ4mmlOWt4SOOubIKDpcG5sSZh5jayZ'
        srdr = hby1.db.evts.get(keys=(ghab.pre, diger.qb64b))

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

        assert srdr is not None and srdr.raw == raw

        # Grab the group ROT event, sign with Hab2 and parse into Kev1
        sigers = hab2.mgr.sign(srdr.raw, verfers=hab2.kever.verfers, indexed=True, indices=[1])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
        assert msg[srdr.size:] == (b'-AABABC4sYnDXCpO87BMXO21ofqHZKntPSdEXlBPlq1H8NOHD3KV-GHGWrXyrElK'
                                     b'BkQNBbNr9_yg-nSnBq7N9rAxEFcK')
        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception

        # Now sign the group ROT with Hab3 and parse into Kev1.  This should commit the event
        sigers = hab3.mgr.sign(srdr.raw, verfers=hab3.kever.verfers, indexed=True, indices=[2])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
        assert msg[srdr.size:] == (b'-AABACAXyUueUfXC-ccUxBZTgnyHTXOy1wUYgQrhlk8FMJGQPiaOOdAzhaW71JeF'
                                     b'0By8Se-tKKuPP1xG41DblgXIwNkE')

        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev1, local=True)  # parse second signed group inception
        kev1.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor.processEscrows()  # Get the rest of the way through counselor.
        assert counselor.complete(prefixer=prefixer, number=number, diger=diger)
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
        msgs = [hab1.replay(version=TEST_VERSION),
                hab2.replay(version=TEST_VERSION),
                hab3.replay(version=TEST_VERSION),
                ghab.replay(version=TEST_VERSION)]
        kevs = [kev4, kev5, kev6, kev7]
        for (kev, msg) in [(kev, msg) for kev in kevs for msg in msgs]:
            Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev, local=True)

        assert kev4.kevers[ghab.pre] is not None
        assert kev5.kevers[ghab.pre] is not None
        assert kev6.kevers[ghab.pre] is not None
        assert kev7.kevers[ghab.pre] is not None

        # Create a new counselor with #4
        counselor4 = Counselor(hby=hby4)

        hab4.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        hab5.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        hab6.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        merfers = [hab4.kever.verfers[0], hab5.kever.verfers[0], hab6.kever.verfers[0]]
        migers = [hab4.kever.ndigers[0], hab5.kever.ndigers[0], hab6.kever.ndigers[0]]
        prefixer = Prefixer(qb64=ghab.pre)
        number = Number(sn=ghab.kever.sn + 1)
        rot = ghab4.rotate(isith='["1/3", "1/3", "1/3"]', nsith='["1/3", "1/3", "1/3"]',
                           toad=0, cuts=list(), adds=list(), verfers=merfers,
                           digers=migers, framed=True, **KWA, gvrsn=TEST_VERSION)
        rserder = SerderKERI(raw=rot)

        counselor4.start(ghab=ghab4, prefixer=prefixer, number=number, diger=Diger(qb64=rserder.said))

        # partially signed group rotation
        val = hby4.db.gpse.get(keys=(ghab4.pre,))
        (number, diger) = val[0]
        assert number.sn == 3
        assert diger.qb64b == b'EGt_CZZASnY_iyB14ZXGQ4MxMtcSVW5oMHAuLM8BnqxV'
        srdr = hby4.db.evts.get(keys=(ghab4.pre, diger.qb64b))

        raw = (b'{"v":"KERI10JSON00023c_","t":"rot","d":"EGt_CZZASnY_iyB14ZXGQ4MxMtcSVW5oMHAu'
               b'LM8BnqxV","i":"EL-f5D0esAFbZTzK9W3wtTgDmncye9IOnF0Z8gRdICIU","s":"3","p":"EH'
               b'V57zdXq3lB3PZ4mmlOWt4SOOubIKDpcG5sSZh5jayZ","kt":["1/3","1/3","1/3"],"k":["D'
               b'OKBAV-_3Z63w7yGmzu6pZCdUlpnEytbnChUhiTZGLa_","DOKFe0a-q2yyi_Yyh9wxLsSnG9e3nx'
               b'vAXlgMaIFSo0YE","DKq5vZxsl7lCtFkuxSdfRRm-Edzdk_mRnh3xlVESXpck"],"nt":["1/3",'
               b'"1/3","1/3"],"n":["EGX_K2uTEU6NOXfNo0VfhYLMrqADYHOoNk7WtT1SXOo2","EFl4us5uR0'
               b'hCiYcW7YyOaSAo-7zp8x1uBVU2E_tmhEwj","EMyxeTiM_cH5IHUI6nummgHMeW-_1oKw7rvqlDd'
               b'gha9v"],"bt":"0","br":[],"ba":[],"a":[]}')
        assert srdr is not None and srdr.raw == raw

        # Grab the group ROT event, sign with Hab5 and parse into Kev4
        sigers = hab5.mgr.sign(srdr.raw, verfers=hab5.kever.verfers, indexed=True, indices=[1], ondices=[4])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
        assert msg[srdr.size:] == (b'-AAB2AABAEDSs99oM-KOhJ8q3H8lqGqPE3EvZxCHvCjZFvWHLzhqm91YlcskGqvK'
                                     b'8DwCg9dj8wRZP54ienzD52EIKvJWWh4J')
        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev4, local=True)  # parse second signed group inception

        # Now sign the group ROT with Hab6 and parse into Kev4.  This should commit the event
        sigers = hab6.mgr.sign(srdr.raw, verfers=hab6.kever.verfers, indexed=True, indices=[2], ondices=[5])
        msg = messagize(serder=srdr, sigers=sigers, framed=True, gvrsn=TEST_VERSION)
        assert msg[srdr.size:] == (b'-AAB2AACAFBNVTM0Gw4rSd-S5HQ_KpmBfDedi7XNvB24ijMjQaekIfKlcdguPS8p'
                                     b'ax9ht7EE3SiTj9fSO_3f4SVUfJMPmHIK')

        Parser(version=TEST_VERSION).parse(ims=bytearray(msg), kvy=kev4, local=True)  # parse second signed group inception
        kev4.processEscrows()  # Run escrows for Kevery1 so he processes all sigs together

        counselor4.processEscrows()  # Get the rest of the way through counselor.
        assert counselor4.complete(prefixer=prefixer, number=number, diger=diger)

        # Validate successful partial rotation
        nkeys = [hab4.kever.verfers[0].qb64, hab5.kever.verfers[0].qb64, hab6.kever.verfers[0].qb64]
        ndigs = [hab4.kever.ndigers[0].qb64, hab5.kever.ndigers[0].qb64, hab6.kever.ndigers[0].qb64]
        assert ghab4.kever.sn == 3
        assert [verfer.qb64 for verfer in ghab4.kever.verfers] == nkeys
        assert [diger.qb64 for diger in ghab4.kever.ndigers] == ndigs


@contextmanager
def openMultiSig(prefix="test", salt=b'0123456789abcdef', temp=True, **kwa):
    with openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=temp, **KWA) as (hby1, hab1), \
            openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=temp, **KWA) as (hby2, hab2), \
            openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=temp, **KWA) as (hby3, hab3):
        # Keverys so we can process each other's inception messages.
        kev1 = Kevery(db=hab1.db, lax=True, local=False)
        kev2 = Kevery(db=hab2.db, lax=True, local=False)
        kev3 = Kevery(db=hab3.db, lax=True, local=False)

        icp1 = hab1.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp1), kvy=kev2, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp1), kvy=kev3, local=True)
        icp2 = hab2.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp2), kvy=kev1, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp2), kvy=kev3, local=True)
        icp3 = hab3.msgOwnEvent(sn=0, framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp3), kvy=kev1, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(icp3), kvy=kev2, local=True)

        smids = [hab1.pre, hab2.pre, hab3.pre]
        rmids = None

        inits = dict(
            toad=0,
            wits=[],
            isith='3',
            nsith='3',
            **KWA
        )

        ghab1 = hby1.makeGroupHab(group=f"{prefix}_group1", mhab=hab1,
                                  smids=smids, rmids=rmids, **inits)
        ghab2 = hby2.makeGroupHab(group=f"{prefix}_group2", mhab=hab2,
                                  smids=smids, rmids=rmids, **inits)
        ghab3 = hby3.makeGroupHab(group=f"{prefix}_group3", mhab=hab3,
                                  smids=smids, rmids=rmids, **inits)

        eserder = hab1.db.evts.get(keys=(ghab1.pre.encode("utf-8"), ghab1.pre.encode("utf-8")))
        sigers = bytearray()
        for hab in [hab1, hab2, hab3]:
            for siger in hab.db.sigs.get(keys=(ghab1.pre.encode("utf-8"), ghab1.pre.encode("utf-8"))):
                sigers.extend(siger.qb64b)

        evt = bytearray(eserder.raw)
        evt.extend(Counter(Codens.ControllerIdxSigs,
                                count=3, version=TEST_VERSION).qb64b)  # attach cnt
        evt.extend(sigers)

        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev3, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev2, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(evt), kvy=kev1, local=True)

        assert ghab1.pre in kev1.kevers
        assert ghab1.pre in kev2.kevers
        assert ghab1.pre in kev3.kevers

        yield (hby1, ghab1), (hby2, ghab2), (hby3, ghab3)


def test_multisig_incept(mockHelpingNowUTC):
    with openHab(name="test", temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        exn, atc = multisigInceptExn(hab=hab, smids=aids, rmids=aids,
                                     icp=hab.msgOwnEvent(sn=hab.kever.sn,
                                                         framed=True, gvrsn=TEST_VERSION),
                                     version=TEST_VERSION,
                                     kind=Kinds.json)

        assert exn.ked["r"] == '/multisig/icp'
        assert exn.saidb == b'EJ6Kl50IBicAa8zND_3wMSQ5itw555V7NKid9y1SKobe'
        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3MAAAEIaGMMWJFPmt'
                    b'XznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAACL4cf7LxzKJgaJbb7wWHLuTfj3'
                    b'wManDV0SW7euFNZDiEhD1kUiP3_wtOIfqB_ZsEceE4oIgOOZwFROyrcf9ScB-LAa'
                    b'5AACAA-e-icp-AABAACihaKoLnoXxRoxGbFfOy67YSh6UxtgjT2oxupnLDz2Flhe'
                    b'vGJKTMObbdex9f0Hqob6uTavSJvsXf5RzitskkkC')
        data = exn.ked["a"]
        assert data["smids"] == aids
        assert "icp" in exn.ked['e']


def test_multisig_incept_explicit_v1_uses_legacy_special_exn(mockHelpingNowUTC, monkeypatch):
    with openHab(name="test", temp=True, salt=b'0123456789abcdef', **KWA) as (_, hab):
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        icp = hab.msgOwnEvent(sn=hab.kever.sn, framed=True, gvrsn=TEST_VERSION)
        special_calls = {}
        endorse_calls = {}
        original_special_exchange = grouping.specialExchange
        original_endorse = hab.endorse

        def capture_special_exchange(*, sender, route, modifiers, attributes, embeds, version, kind):
            special_calls["version"] = version
            special_calls["kind"] = kind
            return original_special_exchange(sender=sender,
                                             route=route,
                                             modifiers=modifiers,
                                             attributes=attributes,
                                             embeds=embeds,
                                             version=version,
                                             kind=kind)

        def capture_endorse(*args, **kwargs):
            endorse_calls["gvrsn"] = kwargs.get("gvrsn")
            return original_endorse(*args, **kwargs)

        monkeypatch.setattr(grouping, "specialExchange", capture_special_exchange)
        monkeypatch.setattr(hab, "endorse", capture_endorse)

        multisigInceptExn(hab=hab, smids=aids, rmids=aids, icp=icp,
                          version=Vrsn_1_0, kind=Kinds.json)

        assert special_calls["version"] == Vrsn_1_0
        assert special_calls["kind"] == Kinds.json
        assert endorse_calls["gvrsn"] == Vrsn_1_0


def test_multisig_incept_default_version_uses_v2_nested_substreams(mockHelpingNowUTC):
    V2_KWA = dict(version=Vrsn_2_0, kind=Kinds.json)

    with openHab(name="test", temp=True, salt=b'0123456789abcdef', **V2_KWA) as (_, hab):
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        icp = hab.msgOwnEvent(sn=hab.kever.sn, framed=True, gvrsn=Version)
        innerSerder = SerderKERI(raw=icp)
        exn, atc = multisigInceptExn(hab=hab, smids=aids, rmids=aids, icp=icp,
                                     kind=Kinds.json)

        assert exn.ked["r"] == '/multisig/icp'
        data = exn.ked["a"]
        assert data["gid"] == innerSerder.pre
        assert data["smids"] == aids
        assert data["rmids"] == aids
        assert data["embeds"]["icp"] == innerSerder.said
        assert "d" in data["embeds"]
        assert "e" not in exn.ked

        results = Parser(version=Vrsn_2_0).parse(ims=bytearray(exn.raw + atc),
                                                 framed=True,
                                                 processive=False)
        assert len(results) == 1
        assert len(results[0].nests) == 1
        assert results[0].nests[0].serder.said == innerSerder.said


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
        exn, atc = multisigRotateExn(ghab=ghab1, smids=ghab1.smids, rmids=ghab1.rmids, rot=rot,
                                     version=TEST_VERSION, kind=Kinds.json)

        assert exn.ked["r"] == '/multisig/rot'
        assert exn.saidb == b'EL4LeEHvTiOxs1UDNTv5qWxCYVYojdpEMfKI62O-UsPm'
        assert atc == (b'-FABEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkabaMAAAEH__mobl7NDy'
                    b'yQCB1DoLK-OPSueraPtZAlWEjfOYkaba-AABAACH_qI1JebS_iehZT6XmvxylpOy'
                    b'2hS2BjO41e4mNmscSBdun2MyGk82SC-rHfQfvDJZlRRwNhLw-pKKKxql8wUF')
        data = exn.ked["a"]
        assert data["smids"] == ghab1.smids
        assert data["gid"] == ghab1.pre
        assert "rot" in exn.ked["e"]


def test_multisig_interact(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):
        ixn = ghab1.mhab.interact(framed=True, **KWA, gvrsn=TEST_VERSION)
        exn, atc = multisigInteractExn(ghab=ghab1, aids=ghab1.smids,
                                       ixn=ixn,
                                       version=TEST_VERSION,
                                       kind=Kinds.json)

        assert exn.ked["r"] == '/multisig/ixn'
        assert exn.saidb == b'EDF8o6SK-s2jxUVnlGtqAVtXTF-wyZ26c0dUsS5p766q'
        assert atc == (b'-FABEH__mobl7NDyyQCB1DoLK-OPSueraPtZAlWEjfOYkabaMAAAEH__mobl7NDy'
                    b'yQCB1DoLK-OPSueraPtZAlWEjfOYkaba-AABAABFfU5so86inNogCPN7Ko8WXvkM'
                    b'KeiUKPScQ3FYrVmngNpVmW8xmhOTfixuWFlLcQPjEf3bRQhvNvx7azcI_vwB-LAa'
                    b'5AACAA-e-ixn-AABAABG58m7gibjdrQ8YU-8WQ8A70nctYekYr3xdfZ5WgDQOD0b'
                    b'b9pI7SuuaJvzfAQisLAYQnztA82pAo1Skhf1vQwD')
        data = exn.ked["a"]
        assert data["smids"] == ghab1.smids
        assert data["gid"] == ghab1.pre
        assert "ixn" in exn.ked["e"]


def test_multisig_registry_incept(mockHelpingNowUTC, mockCoringRandomNonce):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, _), (_, _)):
        vcp = incept(ghab1.pre, **KWA)
        ixn = ghab1.mhab.interact(data=[dict(i=vcp.pre, s="0", d=vcp.said)],
                                  framed=True, **KWA, gvrsn=TEST_VERSION)
        exn, atc = multisigRegistryInceptExn(ghab=ghab1, vcp=vcp.raw, anc=ixn,
                                             usage="Issue vLEI Credentials",
                                             version=TEST_VERSION,
                                             kind=Kinds.json)

        assert exn.ked["r"] == '/multisig/vcp'
        assert exn.saidb == b'EBum6f9SwkUUjQTl_vDplKs7L-shzQT6fS5jJlzdP9PP'
        assert atc == (b'-FABEDEf72ZZ9mhpT1Xz-_YkXl7cg93sjZUFLIsxaFNTbXQOMAAAEDEf72ZZ9mhp'
                    b'T1Xz-_YkXl7cg93sjZUFLIsxaFNTbXQO-AABAAAS5k5D9jH0rbS6jCtZIPyTJRS2'
                    b'l8TZBnChwG8try3kZUJuiAPoBLo7UuhFYmZlpTZ6MfSgcDS7XNg0ETj6L3QF-LAa'
                    b'5AACAA-e-anc-AABAABXlwkzbp_tC4MEbx1Uyny1o7dBGHrYjU3u90Mhv2GtrIGG'
                    b'-7va1jZnlXef2R_LM4TRN8_XjmpLv1skcJaM90UB')
        data = exn.ked["a"]
        assert data == {'gid': 'EEVG5a8c88Fg9vH-6zQP6gJdc4LxVbUTRydx-JhpDcob',
                        'usage': 'Issue vLEI Credentials'}
        assert "vcp" in exn.ked["e"]
        assert "anc" in exn.ked["e"]


def test_multisig_incept_handler(mockHelpingNowUTC):
    with openHab(name="test0", temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]
        exn, atc = multisigInceptExn(hab=hab, smids=aids, rmids=aids,
                                     icp=hab.msgOwnEvent(sn=hab.kever.sn,
                                                         framed=True, gvrsn=TEST_VERSION),
                                     version=TEST_VERSION,
                                     kind=Kinds.json)

        notifier = Notifier(hby=hby)
        mux = Multiplexor(hby=hby, notifier=notifier)
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(exc=exc, mux=mux)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=TEST_VERSION).parseOne(ims=ims, exc=exc)
        assert len(notifier.signaler.signals) == 0

        esaid = exn.ked['e']['d']
        digers = hby.db.meids.get(keys=(esaid, ))
        assert len(digers) == 1
        assert digers[0].qb64 == exn.said
        prefixers = hby.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 1
        assert prefixers[0].qb64 == exn.pre


def test_multisig_incept_handler_parses_approved_v1_embed(mockHelpingNowUTC):
    with openHab(name="approved-embed1", salt=b'0123456789abcdef',
                 transferable=True, temp=True, **KWA) as (hby1, hab1), \
            openHab(name="approved-embed2", salt=b'abcdef0123456789',
                    transferable=True, temp=True, **KWA) as (hby2, hab2):
        Parser(version=TEST_VERSION).parse(ims=bytearray(hab2.msgOwnEvent(sn=0, framed=True,
                                                                          gvrsn=TEST_VERSION)),
                                           kvy=hby1.kvy, local=True)
        Parser(version=TEST_VERSION).parse(ims=bytearray(hab1.msgOwnEvent(sn=0, framed=True,
                                                                          gvrsn=TEST_VERSION)),
                                           kvy=hby2.kvy, local=True)

        smids = [hab1.pre, hab2.pre]
        inits = dict(toad=0, wits=[], isith="2", nsith="2", **KWA)
        ghab1 = hby1.makeGroupHab(group="approved-embed", mhab=hab1,
                                  smids=smids, rmids=None, **inits)
        ghab2 = hby2.makeGroupHab(group="approved-embed", mhab=hab2,
                                  smids=smids, rmids=None, **inits)

        icp1 = ghab1.msgOwnInception(allowPartiallySigned=True)
        exn1, _ = multisigInceptExn(hab=ghab1.mhab, smids=ghab1.smids,
                                    rmids=ghab1.rmids, icp=icp1,
                                    version=TEST_VERSION, kind=Kinds.json)
        icp2 = ghab2.msgOwnInception(allowPartiallySigned=True)
        exn2, atc2 = multisigInceptExn(hab=ghab2.mhab, smids=ghab2.smids,
                                       rmids=ghab2.rmids, icp=icp2,
                                       version=TEST_VERSION, kind=Kinds.json)

        notifier = Notifier(hby=hby1)
        mux = Multiplexor(hby=hby1, notifier=notifier)
        exc = Exchanger(hby=hby1, handlers=[])
        loadHandlers(exc=exc, mux=mux)

        mux.add(exn1)  # Record local approval before the matching peer proposal arrives.
        ims = bytearray(exn2.raw)
        ims.extend(atc2)
        Parser(version=TEST_VERSION).parseOne(ims=ims, exc=exc)

        serder = SerderKERI(raw=icp1)
        sigers = hby1.db.sigs.get(keys=(serder.preb, serder.saidb))
        assert [siger.index for siger in sigers] == [0, 1]


def test_multisig_incept_handler_v2_with_kram(mockHelpingNowUTC):
    V2_KWA = dict(version=Vrsn_2_0, kind=Kinds.json)

    # Create two member habitats that will each build the same 2-of-2 group
    # inception proposal from their own local perspective
    with openHab(name="approved-nested1", salt=b'0123456789abcdef',
                 transferable=True, temp=True, **V2_KWA) as (hby1, hab1), \
            openHab(name="approved-nested2", salt=b'abcdef0123456789',
                    transferable=True, temp=True, **V2_KWA) as (hby2, hab2):

        # Exchange the member AID inception events first so each side knows the
        # other participant before creating the shared group habitat
        Parser(version=Vrsn_2_0).parse(ims=bytearray(hab2.msgOwnEvent(sn=0, framed=True,
                                                                      gvrsn=Vrsn_2_0)),
                                       kvy=hby1.kvy, local=True)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(hab1.msgOwnEvent(sn=0, framed=True,
                                                                      gvrsn=Vrsn_2_0)),
                                       kvy=hby2.kvy, local=True)

        # Both members participate in signing this group inception
        smids = [hab1.pre, hab2.pre]
        inits = dict(toad=0, wits=[], isith="2", nsith="2", **V2_KWA)

        # Build the same group habitat on both sides
        ghab1 = hby1.makeGroupHab(group="approved-nested", mhab=hab1,
                                  smids=smids, rmids=None, **inits)
        ghab2 = hby2.makeGroupHab(group="approved-nested", mhab=hab2,
                                  smids=smids, rmids=None, **inits)

        # Member 1 creates a partially signed group inception and wraps it in a
        # V2 /multisig/icp exchange
        icp1 = ghab1.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=Vrsn_2_0)
        exn1, atc1 = multisigInceptExn(hab=ghab1.mhab, smids=ghab1.smids,
                                       rmids=ghab1.rmids, icp=icp1,
                                       version=Vrsn_2_0, kind=Kinds.json)

        # Member 2 independently creates its matching partially signed copy and
        # wraps it in the same V2 /multisig/icp exchange route
        icp2 = ghab2.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=Vrsn_2_0)
        exn2, atc2 = multisigInceptExn(hab=ghab2.mhab, smids=ghab2.smids,
                                       rmids=ghab2.rmids, icp=icp2,
                                       version=Vrsn_2_0, kind=Kinds.json)

        notifier = Notifier(hby=hby1)
        mux = Multiplexor(hby=hby1, notifier=notifier)
        exc = Exchanger(hby=hby1, handlers=[])
        loadHandlers(exc=exc, mux=mux)

        # Seed "local approval already exists" directly in the mux. For V2 the
        # wrapped group inception is carried in nested substreams, so we parse
        # the local stream without processing it in order to recover `nests`
        local = Parser(version=Vrsn_2_0).parse(ims=bytearray(exn1.raw + atc1),
                                               framed=True,
                                               processive=False)[0]
        mux.add(local.serder, nests=local.nests)

        with openCF(name="grouping-kram", base="test") as cf:
            # Send the Member 2's exchange through the real V2 path:
            # Parser -> Kevery.processMsg -> Kramer -> Exchanger -> mux.add
            config = {
                "kram": {
                    "enabled": True,
                    "denials": [],
                    "caches": {
                        "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                    }
                },
                "dt": "2021-01-01T00:00:00.000000+00:00",
            }
            cf.put(config)
            kvy = Kevery(db=hby1.db, lax=False, local=False,
                         kramer=Kramer(db=hby1.db, cf=cf), exc=exc)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(exn2.raw + atc2),
                                           kvy=kvy,
                                           exc=exc,
                                           local=False)

        # Once Member 2's proposal is accepted, the inner
        # group inception should have both members' signatures on it
        serder = SerderKERI(raw=icp1)
        sigers = hby1.db.sigs.get(keys=(serder.preb, serder.saidb))
        assert [siger.index for siger in sigers] == [0, 1]


def test_multisig_rotate_handler(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (hby2, ghab2), (_, _)):
        msg = ghab1.mhab.rotate(framed=True, **KWA, gvrsn=TEST_VERSION)
        notifier = Notifier(hby=hby1)
        mux = Multiplexor(hby=hby1, notifier=notifier)
        exc = Exchanger(hby=hby1, handlers=[])
        loadHandlers(exc=exc, mux=mux)

        # create and send message from ghab2
        exn, atc = multisigRotateExn(ghab=ghab2, smids=ghab1.smids, rmids=ghab1.rmids,
                                     rot=msg, version=TEST_VERSION, kind=Kinds.json)
        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=TEST_VERSION).parseOne(ims=ims, exc=exc)

        # One notification
        assert len(notifier.signaler.signals) == 1

        esaid = exn.ked['e']['d']
        digers = hby1.db.meids.get(keys=(esaid, ))
        assert len(digers) == 1
        assert digers[0].qb64 == exn.said
        prefixers = hby1.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 1
        assert prefixers[0].qb64 == ghab2.mhab.pre

        # Send the same message from ghab1
        exn, atc = multisigRotateExn(ghab=ghab1, smids=ghab1.smids, rmids=ghab1.rmids,
                                     rot=msg, version=TEST_VERSION, kind=Kinds.json)
        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=TEST_VERSION).parseOne(ims=ims, exc=exc)

        # There should still only be one notification because we don't notify for our own event
        assert len(notifier.signaler.signals) == 1

        digers = hby1.db.meids.get(keys=(esaid, ))
        assert len(digers) == 2
        assert digers[1].qb64 == exn.said
        prefixers = hby1.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 2
        assert prefixers[1].qb64 == ghab1.mhab.pre


def test_multisig_interact_handler(mockHelpingNowUTC):
    with openMultiSig(prefix="test") as ((hby1, ghab1), (_, ghab2), (_, _)):
        ixn = ghab1.mhab.interact(framed=True, **KWA, gvrsn=TEST_VERSION)
        exn, atc = multisigInteractExn(ghab=ghab2, aids=ghab1.smids,
                                       ixn=ixn,
                                       version=TEST_VERSION,
                                       kind=Kinds.json)

        notifier = Notifier(hby=hby1)
        mux = Multiplexor(hby=hby1, notifier=notifier)
        exc = Exchanger(hby=hby1, handlers=[])
        loadHandlers(exc=exc, mux=mux)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=TEST_VERSION).parseOne(ims=ims, exc=exc)

        esaid = exn.ked['e']['d']
        assert len(notifier.signaler.signals) == 1
        digers = hby1.db.meids.get(keys=(esaid, ))
        assert len(digers) == 1
        assert digers[0].qb64 == exn.said
        prefixers = hby1.db.maids.get(keys=(esaid,))
        assert len(prefixers) == 1
        assert prefixers[0].qb64 == ghab2.mhab.pre
