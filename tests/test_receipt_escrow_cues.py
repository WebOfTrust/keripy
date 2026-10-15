"""
tests.receipt_escrow_cues module
"""

from types import SimpleNamespace

from hio.help import decking
import pytest

from keri.app import delegating, grouping
from keri.app.agenting import Receiptor
from keri.core import Diger, Number, NumDex
from keri.vdr.credentialing import Registrar


class Store:
    def __init__(self, items=()):
        self.items = list(items)
        self.removed = []
        self.added = []
        self.pinned = []

    def getTopItemIter(self):
        return iter(self.items)

    def rem(self, keys):
        self.removed.append(keys)

    def add(self, keys, val):
        self.added.append((keys, val))

    def put(self, keys, val):
        self.added.append((keys, val))

    def pin(self, keys, val):
        self.pinned.append((keys, val))


def _cue(pre, sn):
    return dict(pre=pre, sn=sn)


def test_registrar_consumes_only_advanced_cues_and_preserves_order():
    pre = "ERegistrar"
    unrelated = _cue("EUnrelated", 99)
    cues = decking.Deck([unrelated, *(_cue(pre, sn) for sn in range(3))])
    entries = []
    for sn in range(3):
        number = Number(num=sn)
        snq = Number(num=sn, code=NumDex.Huge).qb64
        entries.append((("ERegistry", snq),
                        (SimpleNamespace(qb64=pre, qb64b=pre.encode()), number,
                         SimpleNamespace(qb64=f"EDigest{sn}", qb64b=f"EDigest{sn}".encode()))))

    tpwe, tede = Store(entries), Store()
    registrar = Registrar.__new__(Registrar)
    registrar.receiptRequests = set()
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"])},
        habs={pre: SimpleNamespace(pre=pre)},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: ["wig"])),
    )
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=tpwe, tede=tede))
    registrar.receiptor = SimpleNamespace(msgs=decking.Deck(), cues=cues, active=None)

    registrar.processWitnessEscrow()

    assert len(tede.added) == 3
    assert len(tpwe.removed) == 3
    assert list(cues) == [unrelated]


def test_registrar_retains_cue_while_receipts_are_pending():
    pre = "ERegistrar"
    cue = _cue(pre, 1)
    cues = decking.Deck([cue])
    number = Number(num=1)
    snq = Number(num=1, code=NumDex.Huge).qb64
    prefixer = SimpleNamespace(qb64=pre, qb64b=pre.encode())
    diger = SimpleNamespace(qb64="EDigest", qb64b=b"EDigest")
    tpwe = Store([((regk, snq), (prefixer, number, diger))
                  for regk in ("ERegistryA", "ERegistryB")])
    tede = Store()
    registrar = Registrar.__new__(Registrar)
    registrar.receiptRequests = set()
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"]),
                "EMissing": SimpleNamespace(wits=["EWitness"])},
        habs={pre: SimpleNamespace(pre=pre)},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: [])),
    )
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=tpwe, tede=tede))
    registrar.receiptor = SimpleNamespace(msgs=decking.Deck(), cues=cues, active=None)
    registrar.receiptRequests.add((pre, 1))

    registrar.processWitnessEscrow()

    assert list(cues) == [cue]
    assert registrar.receiptRequests == {(pre, 1)}
    assert len(tpwe.items) == 2
    assert not tpwe.removed
    assert not tede.added


def test_registrar_advances_all_escrows_for_one_completed_event():
    pre, sn, digest = "ERegistrar", 5, "EDigest"
    number = Number(num=sn)
    prefixer = SimpleNamespace(qb64=pre, qb64b=pre.encode())
    diger = SimpleNamespace(qb64=digest, qb64b=digest.encode())
    snq0 = Number(num=0, code=NumDex.Huge).qb64
    snq1 = Number(num=1, code=NumDex.Huge).qb64
    entries = [(("ECredentialA", snq0), (prefixer, number, diger)),
               (("ECredentialB", snq1), (prefixer, number, diger))]
    unrelated = _cue("EUnrelated", 99)
    cues = decking.Deck([unrelated, _cue(pre, sn)])
    tpwe, tede = Store(entries), Store()
    registrar = Registrar.__new__(Registrar)
    registrar.receiptRequests = set()
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"])},
        habs={pre: SimpleNamespace(pre=pre)},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: ["wig"])),
    )
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=tpwe, tede=tede))
    registrar.receiptor = SimpleNamespace(msgs=decking.Deck(), cues=cues, active=None)

    registrar.processWitnessEscrow()

    assert len(tede.added) == 2
    assert len(tpwe.removed) == 2
    assert list(cues) == [unrelated]


def test_registrar_callers_deduplicate_receipt_request_for_shared_anchor():
    pre, sn = "ERegistrar", 5
    diger = Diger(ser=b"anchor")
    hab = SimpleNamespace(
        pre=pre,
        kever=SimpleNamespace(
            sner=SimpleNamespace(num=sn),
            serder=SimpleNamespace(said=diger.qb64),
            prefixer=SimpleNamespace(qb64=pre, qb64b=pre.encode()),
        ),
    )
    registries = {
        name: SimpleNamespace(regk=name, hab=hab, anchorMsg=lambda **kwa: None)
        for name in ("ERegistryIncept", "ERegistryIssue", "ERegistryRevoke")
    }
    tpwe, tede = Store(), Store()
    msgs, cues = decking.Deck(), decking.Deck()
    receiptor = SimpleNamespace(msgs=msgs, cues=cues, active=None)
    registrar = Registrar.__new__(Registrar)
    registrar.receiptRequests = set()
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"])},
        habs={pre: hab},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: ["wig"])),
    )
    registrar.rgy = SimpleNamespace(
        regs=registries,
        reger=SimpleNamespace(tpwe=tpwe, tede=tede),
    )
    registrar.receiptor = receiptor

    registrar.incept(
        iserder=SimpleNamespace(pre="ERegistryIncept", said="ETelInception"),
        anc=SimpleNamespace(pre=pre, sn=sn),
    )
    registrar.issue(
        creder=SimpleNamespace(regid="ERegistryIssue"),
        iserder=SimpleNamespace(ked={"i": "ECredentialIssue", "s": "0"}, said="EIssuance"),
        anc=None,
    )
    assert len(msgs) == 1
    assert msgs.popleft() == _cue(pre, sn)
    receiptor.active = (pre, sn)
    registrar.revoke(
        creder=SimpleNamespace(regid="ERegistryRevoke"),
        rserder=SimpleNamespace(ked={"i": "ECredentialRevoke", "s": "1"}, said="ERevocation"),
        anc=None,
    )
    assert not msgs

    tpwe.items.extend(tpwe.added)
    cues.push(_cue(pre, sn))
    receiptor.active = None
    registrar.processWitnessEscrow()

    assert len(tede.added) == 3
    assert not cues
    assert not registrar.receiptRequests

    registrar._requestReceipts(pre, sn + 1)
    assert list(msgs) == [_cue(pre, sn + 1)]


def test_failed_receipt_request_can_be_queued_again(monkeypatch):
    pre, sn = "ERegistrar", 5
    receiptor = Receiptor(hby=SimpleNamespace())

    def failed_receipt(pre, sn, auths):
        yield receiptor.tock
        raise RuntimeError("receipt failed")

    monkeypatch.setattr(receiptor, "receipt", failed_receipt)
    receiptor.msgs.append(_cue(pre, sn))
    doer = receiptor.witDo(tymth=lambda: 0.0)
    next(doer)
    next(doer)
    with pytest.raises(RuntimeError, match="receipt failed"):
        next(doer)

    registrar = Registrar.__new__(Registrar)
    registrar.receiptRequests = {(pre, sn)}
    registrar.receiptor = receiptor

    prefixer = SimpleNamespace(qb64=pre, qb64b=pre.encode())
    diger = SimpleNamespace(qb64="EDigest", qb64b=b"EDigest")
    snq = Number(num=sn, code=NumDex.Huge).qb64
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"])},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: [])),
    )
    registrar.rgy = SimpleNamespace(
        reger=SimpleNamespace(
            tpwe=Store([(("ERegistry", snq), (prefixer, Number(num=sn), diger))]),
            tede=Store(),
        )
    )
    registrar.processWitnessEscrow()
    assert not registrar.receiptRequests

    registrar._requestReceipts(pre, sn)
    assert list(receiptor.msgs) == [_cue(pre, sn)]
    assert receiptor.active is None


def test_registrar_skips_idle_cue_scan():
    class CountingDeck(list):
        def __init__(self, items=()):
            super().__init__(items)
            self.scans = 0

        def __iter__(self):
            self.scans += 1
            return super().__iter__()

    cues = CountingDeck([_cue("EUnrelated", 99)])
    registrar = Registrar.__new__(Registrar)
    registrar.receiptRequests = set()
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=Store(), tede=Store()))
    registrar.receiptor = SimpleNamespace(msgs=decking.Deck(), cues=cues, active=None)

    registrar.processWitnessEscrow()

    assert cues.scans == 0
    assert list(cues) == [_cue("EUnrelated", 99)]


def test_registrar_discards_late_completion_after_escrow_advanced():
    pre, sn = "ERegistrar", 5
    number = Number(num=sn)
    prefixer = SimpleNamespace(qb64=pre, qb64b=pre.encode())
    diger = SimpleNamespace(qb64="EDigest", qb64b=b"EDigest")
    snq = Number(num=0, code=NumDex.Huge).qb64
    tpwe, tede = Store([(("ECredential", snq), (prefixer, number, diger))]), Store()
    cues = decking.Deck()
    registrar = Registrar.__new__(Registrar)
    registrar.receiptRequests = {(pre, sn)}
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=[])},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: [])),
    )
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=tpwe, tede=tede))
    registrar.receiptor = SimpleNamespace(msgs=decking.Deck(), cues=cues, active=None)

    registrar.processWitnessEscrow()
    assert len(tede.added) == 1
    assert registrar.receiptRequests == {(pre, sn)}

    tpwe.items.clear()
    unrelated = _cue("EUnrelated", 99)
    cues.extend([_cue(pre, sn), unrelated])
    registrar.processWitnessEscrow()

    assert list(cues) == [unrelated]
    assert not registrar.receiptRequests


def _counselor(pre, entries, cues, wigers):
    gpwe, cgms = Store(entries), Store()
    keys = [SimpleNamespace(qb64="EKey")]
    hab = SimpleNamespace(
        pre=pre,
        mhab=SimpleNamespace(kever=SimpleNamespace(verfers=keys)),
    )
    counselor = grouping.Counselor.__new__(grouping.Counselor)
    counselor.hby = SimpleNamespace(
        db=SimpleNamespace(
            gpwe=gpwe,
            cgms=cgms,
            wigs=SimpleNamespace(get=lambda keys: wigers),
        ),
        kevers={pre: SimpleNamespace(wits=["EWitness"], verfers=keys)},
        habs={pre: hab},
    )
    counselor.witDoer = SimpleNamespace(cues=cues, gets=decking.Deck())
    return counselor, gpwe, cgms


def test_counselor_consumes_completed_cues_but_keeps_unrelated_and_pending():
    pre = "EGroup"
    unrelated = _cue("EUnrelated", 99)
    pending = _cue(pre, 10)
    pending_duplicate = _cue(pre, 10)
    cues = decking.Deck([unrelated, *(_cue(pre, sn) for sn in range(3)), pending, pending_duplicate])
    entries = [((pre,), (Number(num=sn), SimpleNamespace(qb64=f"EDigest{sn}")))
               for sn in (*range(3), 10)]
    counselor, gpwe, cgms = _counselor(pre, entries, cues, ["wig"])

    # Keep the last event pending by giving it a different witness count.
    counselor.hby.kevers[pre].wits = ["EWitness", "EOther"]
    counselor.hby.db.wigs.get = lambda keys: ["wig"] if keys[1] == "EDigest10" else ["wig", "other"]
    counselor.processPartialWitnessEscrow()

    assert len(cgms.added) == 3
    assert len(gpwe.removed) == 3
    assert list(cues) == [unrelated, pending, pending_duplicate]


def test_counselor_consumes_all_duplicate_cues_after_advancement():
    pre = "EGroup"
    unrelated = _cue("EUnrelated", 99)
    trailing = _cue("ETrailing", 100)
    cues = decking.Deck([unrelated, _cue(pre, 1), _cue(pre, 1), trailing])
    entry = ((pre,), (Number(num=1), SimpleNamespace(qb64="EDigest")))
    counselor, gpwe, cgms = _counselor(pre, [entry], cues, ["wig"])

    counselor.processPartialWitnessEscrow()

    assert gpwe.removed == [(pre,)]
    assert len(cgms.added) == 1
    assert list(cues) == [unrelated, trailing]


def test_anchorer_consumes_duplicate_cues_after_dispatch_and_retains_missing_hab_cues(monkeypatch):
    pre, delpre = "EDelegate", "EDelegator"
    unrelated = _cue("EUnrelated", 99)
    missing = _cue("EMissing", 4)
    missing_duplicate = _cue("EMissing", 4)
    cues = decking.Deck([_cue(pre, 1), unrelated, _cue(pre, 2), _cue(pre, 2),
                         _cue(pre, 3), missing, missing_duplicate])
    records = [SimpleNamespace(pre=pre, sn=sn, said=f"EDigest{sn}", pvrsn="version")
               for sn in range(1, 4)]
    records.append(SimpleNamespace(pre="EMissing", sn=4, said="EOther", pvrsn="version"))
    dpwe = Store([((record.pre, record.said), record) for record in records])
    dune = Store()
    calls = []
    numbers = {f"EDigest{sn}": sn for sn in range(1, 4)}
    hab = SimpleNamespace(
        pre=pre,
        kever=SimpleNamespace(delpre=delpre),
        kevers={delpre: SimpleNamespace(prefixer=SimpleNamespace(qb64=delpre))},
        db=SimpleNamespace(cloneEvtMsg=lambda **kwa: bytearray(f"{pre}|{kwa['dig']}".encode())),
    )

    class FakeSerder:
        def __init__(self, raw):
            self.pre, self.said = raw.decode().split("|")
            self.sn = numbers[self.said]
            self.snh, self.ilk, self.size = f"{self.sn:x}", "icp", len(raw)
            self.pretty = lambda: "event"

    monkeypatch.setattr(delegating, "SerderKERI", FakeSerder)
    monkeypatch.setattr(
        delegating, "delegateRequestExn",
        lambda *a, **kwa: (SimpleNamespace(pre="EExchange", pretty=lambda: "exn"), b"atc"),
    )
    anchorer = delegating.Anchorer.__new__(delegating.Anchorer)
    anchorer.hby = SimpleNamespace(
        db=SimpleNamespace(
            dpwe=dpwe,
            dune=dune,
            wigs=SimpleNamespace(get=lambda keys: ["wig"]),
        ),
        kevers={pre: SimpleNamespace(wits=["EWitness"]),
                "EMissing": SimpleNamespace(wits=["EWitness"])},
        habs={pre: hab},
    )
    anchorer.witDoer = SimpleNamespace(cues=cues)
    anchorer.proxy = SimpleNamespace(pre="EProxy")
    anchorer.postman = SimpleNamespace(send=lambda **kwa: calls.append("send"))
    anchorer.witq = SimpleNamespace(query=lambda **kwa: calls.append("query"))
    anchorer.version = anchorer.kind = None

    anchorer.processPartialWitnessEscrow()

    assert calls == ["send", "send", "query"] * 3
    assert len(dune.pinned) == 3
    assert dpwe.removed == [(pre, f"EDigest{sn}") for sn in range(1, 4)]
    assert list(cues) == [unrelated, missing, missing_duplicate]


def test_counselor_empty_witness_set_advances_without_cues():
    pre = "EGroup"
    cues = decking.Deck()
    entry = ((pre,), (Number(num=1), SimpleNamespace(qb64="EDigest")))
    counselor, gpwe, cgms = _counselor(pre, [entry], cues, [])
    counselor.hby.kevers[pre].wits = []

    counselor.processPartialWitnessEscrow()

    assert gpwe.removed == [(pre,)]
    assert len(cgms.added) == 1
    assert not cues
