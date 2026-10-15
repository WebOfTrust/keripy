"""
tests.receipt_escrow_cues module
"""

from types import SimpleNamespace

from hio.help import decking

from keri.app import delegating, grouping
from keri.core import Number, NumDex
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
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"])},
        habs={pre: SimpleNamespace(pre=pre)},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: ["wig"])),
    )
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=tpwe, tede=tede))
    registrar.receiptor = SimpleNamespace(cues=cues)

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
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"]),
                "EMissing": SimpleNamespace(wits=["EWitness"])},
        habs={pre: SimpleNamespace(pre=pre)},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: [])),
    )
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=tpwe, tede=tede))
    registrar.receiptor = SimpleNamespace(cues=cues)

    registrar.processWitnessEscrow()

    assert list(cues) == [cue]
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
    registrar.hby = SimpleNamespace(
        kevers={pre: SimpleNamespace(wits=["EWitness"])},
        habs={pre: SimpleNamespace(pre=pre)},
        db=SimpleNamespace(wigs=SimpleNamespace(get=lambda keys: ["wig"])),
    )
    registrar.rgy = SimpleNamespace(reger=SimpleNamespace(tpwe=tpwe, tede=tede))
    registrar.receiptor = SimpleNamespace(cues=cues)

    registrar.processWitnessEscrow()

    assert len(tede.added) == 2
    assert len(tpwe.removed) == 2
    assert list(cues) == [unrelated]


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
    cues = decking.Deck([unrelated, *(_cue(pre, sn) for sn in range(3)), pending])
    entries = [((pre,), (Number(num=sn), SimpleNamespace(qb64=f"EDigest{sn}")))
               for sn in (*range(3), 10)]
    counselor, gpwe, cgms = _counselor(pre, entries, cues, ["wig"])

    # Keep the last event pending by giving it a different witness count.
    counselor.hby.kevers[pre].wits = ["EWitness", "EOther"]
    counselor.hby.db.wigs.get = lambda keys: ["wig"] if keys[1] == "EDigest10" else ["wig", "other"]
    counselor.processPartialWitnessEscrow()

    assert len(cgms.added) == 3
    assert len(gpwe.removed) == 3
    assert list(cues) == [unrelated, pending]


def test_anchorer_consumes_cue_after_dispatch_and_retains_it_if_hab_missing(monkeypatch):
    pre, delpre = "EDelegate", "EDelegator"
    cues = decking.Deck([_cue(pre, 1), _cue("EUnrelated", 99), _cue(pre, 2),
                         _cue(pre, 3), _cue("EMissing", 4)])
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
    assert list(cues) == [_cue("EUnrelated", 99), _cue("EMissing", 4)]


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
