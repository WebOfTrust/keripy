# -*- encoding: utf-8 -*-
"""tests.core.test_kraming module

Tests for KRAM (KERI Request Authentication Mechanism) integration through
processMsg on Kevery.
"""

import pytest

from keri import core, kering
from keri.kering import Vrsn_1_0, Vrsn_2_0
from keri.core import eventing, parsing, coring, Verser
from keri.core.kraming import Kramer, AuthTypes
from keri.app import habbing, configing
from keri.db import basing
from keri.help import helping


def test_auth_type_codex():
    """Test AuthTypeCodex codex pattern"""
    assert AuthTypes.AttachedSealReference == 'asr'
    assert AuthTypes.AttachedSignatureSingleKey == 'assk'
    assert AuthTypes.AttachedSignatureMultiKey == 'asmk'

    # Test codex iterable
    codes = list(AuthTypes)
    assert 'asr' in codes
    assert 'assk' in codes
    assert 'asmk' in codes
    assert len(codes) == 3

def test_configuration():
    """Test Kramer configuration handles valid denials, cache types, and raises appropriate errors"""

    # Test valid denials and caches parsed through Kramer init

    fullDenials = [
        [[1, 0], "", ""],
        [[2, 0], "rpy", ""],
        [[2, 0], "rpy", "/end"]
    ]

    caches = {
        "~": ["100", "2000", "7200000", "172800000", "2000", "7200000", "172800000"],
        "qry": ["50", "1000", "3600000", "86400000", "1000", "3600000", "86400000"],
    }

    validCf = {
        "kram": {
            "enabled": True,
            "denials": fullDenials,
            "caches": caches,
        }
    }

    with configing.openCF(name="kram", base="test") as cf:
        cf.put(validCf)
        with basing.openDB(name="test_config", temp=True) as db:
            kramer = Kramer(db, cf)

            # Enabled flag
            assert kramer.enabled is True
            assert kramer.fullDenials == fullDenials

            # Compact denials
            compact = kramer.denials
            assert len(compact) == 3

            v1b64 = Verser.verToB64(major=1, minor=0)
            assert compact[0] == f"{v1b64}."

            v2b64 = Verser.verToB64(major=2, minor=0)
            assert compact[1] == f"{v2b64}.rpy."
            assert compact[2] == f"{v2b64}.rpy./end"

            # Default cache type
            rec = db.ctyp.get("~")
            assert rec is not None
            assert rec.d == 100
            assert rec.sl == 2000
            assert rec.ll == 7200000
            assert rec.xl == 172800000
            assert rec.psl == 2000
            assert rec.pll == 7200000
            assert rec.pxl == 172800000

            # qry cache type
            rec = db.ctyp.get("qry")
            assert rec is not None
            assert rec.d == 50
            assert rec.sl == 1000

    # Test empty denials and no caches

    emptyCf = {
        "kram": {
            "enabled": False,
            "denials": [],
            "caches": {},
        }
    }

    with configing.openCF(name="kram", base="test") as cf:
        cf.put(emptyCf)
        with basing.openDB(name="test_config_empty", temp=True) as db:
            kramer = Kramer(db, cf)
            assert kramer.enabled is False
            assert kramer.denials == []

    # Test malformed denial (wrong structure)

    badStructCf = {
        "kram": {
            "enabled": True,
            "denials": [["not", "valid"]],
            "caches": {},
        }
    }

    with configing.openCF(name="kram", base="test") as cf:
        cf.put(badStructCf)
        with basing.openDB(name="test_config_bad_struct", temp=True) as db:
            with pytest.raises(kering.KramConfigurationError):
                Kramer(db, cf)

    # Error path: malformed denial (too many elements in version)

    badVersionCf = {
        "kram": {
            "enabled": True,
            "denials": [[1, 2, 3]],
            "caches": {},
        }
    }

    with configing.openCF(name="kram", base="test") as cf:
        cf.put(badVersionCf)
        with basing.openDB(name="test_config_bad_version", temp=True) as db:
            with pytest.raises(kering.KramConfigurationError):
                Kramer(db, cf)

    # Error path: invalid cache type values (non-integer strings)

    badCacheCf = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": ["not", "integers"],
            },
        }
    }

    with configing.openCF(name="kram", base="test") as cf:
        cf.put(badCacheCf)
        with basing.openDB(name="test_config_bad_cache", temp=True) as db:
            with pytest.raises(kering.KramConfigurationError):
                Kramer(db, cf)


_testSigner = core.Salter(raw=b'0123456789abcdef').signer(transferable=True)
TEST_PRE = _testSigner.verfer.qb64

def test_intake():
    """Test intake routes messages through denial, passthrough, and kramit logic"""

    v1b64 = Verser.verToB64(major=1, minor=0)
    v2b64 = Verser.verToB64(major=2, minor=0)

    # --- Denial string generation ---

    # v2 reply with route
    serder = eventing.reply(
        pre=TEST_PRE,
        route="/end/role/add",
        data=dict(name="test"),
        pvrsn=Vrsn_2_0,
    )
    assert Kramer.denial(serder) == f"{v2b64}.rpy./end/role/add"

    # v1 query
    serder = eventing.query(
        route="/logs",
        query=dict(stuff="hello"),
        pvrsn=Vrsn_1_0,
    )
    assert Kramer.denial(serder) == f"{v1b64}.qry./logs"

    # empty route
    serder = eventing.reply(
        pre=TEST_PRE,
        route="",
        data=dict(name="test"),
        pvrsn=Vrsn_2_0,
    )
    assert Kramer.denial(serder) == f"{v2b64}.rpy."

    # --- Disabled: all messages pass through ---

    disabledCf = {
        "kram": {
            "enabled": False,
            "denials": [],
            "caches": {},
        }
    }

    with configing.openCF(name="kram_intake", base="test") as cf:
        cf.put(disabledCf)
        with basing.openDB(name="test_intake_dis", temp=True) as db:
            kramer = Kramer(db, cf)
            serder = eventing.reply(pre=TEST_PRE, route="/test",
                                    data=dict(a=1), pvrsn=Vrsn_2_0)

            result = kramer.intake(serder)
            assert result is serder  # passthrough, same object

    # Test messages matching denials bypass kramit

    enabledCf = {
        "kram": {
            "enabled": True,
            "denials": [
                [[1, 0], "", ""],           # deny all v1
                [[2, 0], "rpy", "/end"],    # deny v2 rpy /end*
            ],
            "caches": {
                "~": ["100", "2000", "7200000", "172800000", "2000", "7200000", "172800000"],
            },
        }
    }

    with configing.openCF(name="kram_intake", base="test") as cf:
        cf.put(enabledCf)
        with basing.openDB(name="test_intake_den", temp=True) as db:
            kramer = Kramer(db, cf)

            # v2 rpy /end/role/add matches denial for rpy + /end
            serder = eventing.reply(
                pre=TEST_PRE,
                route="/end/role/add",
                data=dict(a=1),
                pvrsn=Vrsn_2_0,
            )
            result = kramer.intake(serder)
            assert result is serder  # denied from KRAM, passed through

            # v1 message matches blanket v1 denial
            serder = eventing.reply(
                route="/something",
                data=dict(a=1),
                pvrsn=Vrsn_1_0,
            )
            result = kramer.intake(serder)
            assert result is serder  # denied from KRAM, passed through

            # v2 qry does NOT match any denial — should reach kramit
            serder = eventing.query(
                pre=TEST_PRE,
                route="/logs",
                query=dict(stuff="hello"),
                pvrsn=Vrsn_2_0,
            )

            kramit_called = [False]

            def mock_kramit(msg, **kwa):
                kramit_called[0] = True
                return msg

            kramer.kramit = mock_kramit
            result = kramer.intake(serder)
            assert kramit_called[0] is True
            assert result is serder


# The following four tests provide basic coverage for integration with kevery.processMsg() along the various auth paths

KRAM_INTEGRATION_CONFIG = {
    "kram": {
        "enabled": True,
        "denials": [],
        "caches": {
            "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
        }
    },
    "dt": "2021-01-01T00:00:00.000000+00:00",
    "nel":
        {
            "dt": "2021-01-01T00:00:00.000000+00:00",
            "curls":
                [
                    "tcp://localhost:5621/"
                ]
        },
    "iurls":
        [
            "tcp://localhost:5620/?role=peer&name=tam"
        ],
    "durls":
        [
            "http://127.0.0.1:7723/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
            "http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi",
        ],
    "wurls":
        [
            "http://127.0.0.1:5644/.well-known/keri/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy?name=Root"
        ]
}

def test_assk(mockHelpingNowUTC):
    """Test processMsg with single-key sender (assk auth type).

    Covers: ssgs happy path, cigars happy path, stale message,
    cache idempotency, MissingAuthAttachmentError, MissingSenderKeyStateError.
    """

    # Step 1: Setup

    salt1 = core.Salter(raw=b'0123456789abcdef').qb64
    salt2 = core.Salter(raw=b'0123456789abcdeg').qb64
    salt3 = core.Salter(raw=b'0123456789abcdeh').qb64
    salt4 = core.Salter(raw=b'0123456789abcdei').qb64

    with (habbing.openHby(name="sender", base="test", salt=salt1) as senderHby,
          habbing.openHby(name="senderNT", base="test", salt=salt2) as senderNTHby,
          habbing.openHby(name="receiver", base="test", salt=salt3) as receiverHby,
          habbing.openHby(name="unknown", base="test", salt=salt4) as unknownHby):

        # Create transferable single-key sender (no witnesses)
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1,
                                      transferable=True)
        # Create non-transferable single-key sender
        senderNTHab = senderNTHby.makeHab(name="senderNT", isith='1', icount=1,
                                          transferable=False)
        # Create receiver hab (needed for receiver db context)
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1,
                                          transferable=True)
        # Create unknown sender
        unknownHab = unknownHby.makeHab(name="unknown", isith='1', icount=1,
                                        transferable=True)

        # Parse sender ICPs into receiver's db via a cross-feed Kevery.
        crossKvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        senderNTIcp = senderNTHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(senderNTIcp), kvy=crossKvy)
        assert senderNTHab.pre in crossKvy.kevers

        # Create Kramer with config
        with configing.openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            assert kramer.enabled

            # Create Kevery with kramer for KRAM testing
            kvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)


            # Step 2: ssgs happy path

            # Build v2 qry message with mocked timestamp
            stamp = helping.nowIso8601()
            msg = eventing.query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = coring.Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.d == 1000   # drift from config
            assert cache.ml == 5000  # short lag (assk)

            # Assert downstream processQuery generated a "reply" cue
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"


            # Step 3: cigars happy path (non-transferable sender)

            msg2 = eventing.query(pre=senderNTHab.pre,
                                  route="ksn",
                                  query=dict(i=senderNTHab.pre, src=senderNTHab.pre),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Sign with non-transferable sender's keys
            cigars = senderNTHab.mgr.sign(ser=msg2.raw,
                                          verfers=senderNTHab.kever.verfers,
                                          indexed=False)
            kwa = dict(cigars=cigars)

            kvy.processMsg(msg2, **kwa)

            # Assert cache created for non-transferable sender
            cache = receiverHby.db.msgc.get(keys=(senderNTHab.pre, msg2.said))
            assert cache is not None
            assert cache.mdt == stamp


            # Step 4: Test timeliness against stale message

            # Build qry with timestamp far outside acceptance window
            staleStamp = "2020-01-01T00:00:00.000000+00:00"
            staleMsg = eventing.query(pre=senderHab.pre,
                                      route="ksn",
                                      query=dict(i=senderHab.pre, src=senderHab.pre),
                                      stamp=staleStamp,
                                      pvrsn=Vrsn_2_0)

            staleSigers = senderHab.mgr.sign(ser=staleMsg.raw,
                                             verfers=senderHab.kever.verfers,
                                             indexed=True)
            staleKwa = dict(ssgs=[(prefixer, staleSigers)])

            # kramit returns None -> processMsg returns silently
            kvy.processMsg(staleMsg, **staleKwa)

            # Assert no cache entry created for stale message
            staleCache = receiverHby.db.msgc.get(keys=(senderHab.pre, staleMsg.said))
            assert staleCache is None


            # Step 5: Test cache idempotency

            # Resend the same message + kwa from step 2
            # kramit finds existing cache -> returns None (assk idempotent drop)
            origCache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg.said))
            assert origCache is not None  # still there from step 2

            kvy.processMsg(msg, **dict(ssgs=[(prefixer, sigers)]))

            # Cache entry unchanged, no error raised
            cacheAfter = receiverHby.db.msgc.get(keys=(senderHab.pre, msg.said))
            assert cacheAfter is not None
            assert cacheAfter.mdt == origCache.mdt


            # Step 6. Trigger MissingAuthAttachmentError

            noAuthMsg = eventing.query(pre=senderHab.pre,
                                       route="ksn",
                                       query=dict(i=senderHab.pre, src=senderHab.pre),
                                       stamp=stamp,
                                       pvrsn=Vrsn_2_0)

            with pytest.raises(kering.MissingAuthAttachmentError):
                kvy.processMsg(noAuthMsg)  # empty kwa — no auth attachments


            # Step 7: Trigger MissingSenderKeyStateError

            # Build qry from unknown sender
            unknownMsg = eventing.query(pre=unknownHab.pre,
                                        route="ksn",
                                        query=dict(i=unknownHab.pre, src=unknownHab.pre),
                                        stamp=stamp,
                                        pvrsn=Vrsn_2_0)

            unknownSigers = unknownHab.mgr.sign(ser=unknownMsg.raw,
                                                verfers=unknownHab.kever.verfers,
                                                indexed=True)
            unknownPrefixer = coring.Prefixer(qb64=unknownHab.pre)
            unknownKwa = dict(ssgs=[(unknownPrefixer, unknownSigers)])

            with pytest.raises(kering.MissingSenderKeyStateError):
                kvy.processMsg(unknownMsg, **unknownKwa)

    """Done Test"""


def test_asmk(mockHelpingNowUTC):
    """Test processMsg with multi-key sender (asmk auth type, 2-of-3 threshold).

    Covers: full sigs immediate threshold, partial accumulation then threshold,
    duplicate sig dedup, mixed sig sources (ssgs+tsgs), key state change during
    accumulation, long lag timeliness, cache-exists idempotency.
    """

    # Step 1: Setup

    salt1 = core.Salter(raw=b'0123456789abcdef').qb64
    salt2 = core.Salter(raw=b'0123456789abcdeg').qb64

    with (habbing.openHby(name="mkSender", base="test", salt=salt1) as senderHby,
          habbing.openHby(name="mkReceiver", base="test", salt=salt2) as receiverHby):

        # Create 2-of-3 multi-key sender
        senderHab = senderHby.makeHab(name="mkSender", isith='2', icount=3,
                                      transferable=True)
        assert len(senderHab.kever.verfers) == 3

        # Create receiver hab for db context
        receiverHby.makeHab(name="mkReceiver", isith='1', icount=1,
                            transferable=True)

        # Cross-feed sender ICP to receiver
        crossKvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        # Create Kevery with kramer
        with configing.openCF(name="mkKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            prefixer = coring.Prefixer(qb64=senderHab.pre)
            verfers = senderHab.kever.verfers

            # Sign all 3 keys once, select subsets per test step
            def signMsg(msg):
                return senderHab.mgr.sign(ser=msg.raw, verfers=verfers,
                                          indexed=True)


            # Step 2: Test full sigs immediately meeting threshold

            msg = eventing.query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp,
                                   pvrsn=Vrsn_2_0)
            allSigers = signMsg(msg)
            assert len(allSigers) == 3

            kwa = dict(ssgs=[(prefixer, allSigers)])
            kvy.processMsg(msg, **kwa)

            # Assert msgc cache created, partials empty (threshold met immediately)
            cacheOrig = receiverHby.db.msgc.get(keys=(senderHab.pre, msg.said))
            assert cacheOrig is not None
            assert cacheOrig.ml == 60000  # long lag (asmk)
            assert receiverHby.db.pmkm.get(keys=(senderHab.pre, msg.said)) is None
            assert receiverHby.db.pmks.get(keys=(senderHab.pre, msg.said)) == []
            assert receiverHby.db.pmsk.get(keys=(senderHab.pre, msg.said)) is None

            kvy.cues.clear()


            # Step 3: Partial accumulation

            msg2 = eventing.query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp,
                                   pvrsn=Vrsn_2_0)
            allSigers2 = signMsg(msg2)

            # First delivery, 1 sig (below 2-of-3 threshold)
            kwa = dict(ssgs=[(prefixer, [allSigers2[0]])])
            kvy.processMsg(msg2, **kwa)

            # Assert msgc cache created for partial sigs
            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg2.said))
            assert cache is not None

            # Assert that partial DBs are populated
            pmkm = receiverHby.db.pmkm.get(keys=(senderHab.pre, msg2.said))
            assert pmkm is not None
            pmks = receiverHby.db.pmks.get(keys=(senderHab.pre, msg2.said))
            assert pmks is not None
            assert len(pmks) == 1
            pmsk = receiverHby.db.pmsk.get(keys=(senderHab.pre, msg2.said))
            assert pmsk is not None

            # No cue generated because threshold not met
            assert len(kvy.cues) == 0

            # Second delivery, now 2 of 3 sigs, threshold met
            kwa = dict(ssgs=[(prefixer, [allSigers2[2]])])
            kvy.processMsg(msg2, **kwa)

            # Assert partials got cleaned up
            assert receiverHby.db.pmkm.get(keys=(senderHab.pre, msg2.said)) is None
            assert receiverHby.db.pmks.get(keys=(senderHab.pre, msg2.said)) == []
            assert receiverHby.db.pmsk.get(keys=(senderHab.pre, msg2.said)) is None

            # Assert that downstream dispatch occurred via cue gen
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"
            kvy.cues.clear()


            # Step 4: Test duplicate sig does not double-count

            msg3 = eventing.query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp,
                                   pvrsn=Vrsn_2_0)
            allSigers3 = signMsg(msg3)

            # First delivery, sig index 0
            kvy.processMsg(msg3, **dict(ssgs=[(prefixer, [allSigers3[0]])]))
            pmks = receiverHby.db.pmks.get(keys=(senderHab.pre, msg3.said))
            assert len(pmks) == 1

            # Second delivery: same sig index 0 again
            kvy.processMsg(msg3, **dict(ssgs=[(prefixer, [allSigers3[0]])]))
            pmks_after = receiverHby.db.pmks.get(keys=(senderHab.pre, msg3.said))
            assert len(pmks_after) == 1  # deduped, still 1 unique sig

            kvy.cues.clear()


            # Step 5: Test mixed sig sources, ssgs + tsgs in same kwa

            msg4 = eventing.query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp,
                                   pvrsn=Vrsn_2_0)
            allSigers4 = signMsg(msg4)

            # Get sender's current key state for tsgs
            senderKever = receiverHby.db.kevers[senderHab.pre]
            seqner = coring.Seqner(sn=senderKever.sner.num)
            saider = coring.Saider(qb64=senderKever.serder.said)

            # ssgs with sig index 0, tsgs with sig index 1
            tsg = (prefixer, seqner, saider, [allSigers4[1]])
            kwa = dict(ssgs=[(prefixer, [allSigers4[0]])],
                         tsgs=[tsg])

            kvy.processMsg(msg4, **kwa)

            # Assert both sigs pooled, 2 of 3 threshold met
            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg4.said))
            assert cache is not None
            # Partials cleaned up
            assert receiverHby.db.pmkm.get(keys=(senderHab.pre, msg4.said)) is None

            kvy.cues.clear()


            # Step 6: Key state change during accumulation

            msg5 = eventing.query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp,
                                   pvrsn=Vrsn_2_0)
            allSigers2f = signMsg(msg5)

            # First delivery, 1 sig
            kvy.processMsg(msg5, **dict(ssgs=[(prefixer, [allSigers2f[0]])]))
            assert receiverHby.db.pmks.get(keys=(senderHab.pre, msg5.said)) is not None

            # Rotate sender
            rotMsg = senderHab.rotate()
            parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(rotMsg), kvy=crossKvy)

            # Second sig uses new keys post-rotation
            newSigers = senderHab.mgr.sign(ser=msg5.raw,
                                           verfers=senderHab.kever.verfers,
                                           indexed=True)

            # Second delivery with new-key sig — key state mismatch detected
            kvy.processMsg(msg5, **dict(ssgs=[(prefixer, [newSigers[2]])]))

            # Assert accumulation invalidated by key state change -> returns None
            # The partial DB entries still exist (should we be wiping these here?)
            # No cue generated
            assert len(kvy.cues) == 0

            kvy.cues.clear()


            # Step 7: Test Long lag timeliness
            # Build qry with stamp 30 seconds in past:
            # inside ll (60s) but outside sl (5s)
            lagStamp = "2020-12-31T23:59:30.000000+00:00"
            msg6 = eventing.query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=lagStamp,
                                   pvrsn=Vrsn_2_0)

            # Sign with current (post-rotation) keys
            allSigers2g = senderHab.mgr.sign(ser=msg6.raw,
                                             verfers=senderHab.kever.verfers,
                                             indexed=True)

            kvy.processMsg(msg6, **dict(ssgs=[(prefixer, allSigers2g)]))

            # Assert accepted because multi-key uses long lag (ll=60000ms)
            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg6.said))
            assert cache is not None
            assert cache.ml == 60000  # confirms long lag used

            kvy.cues.clear()

            # Step 8: Test cache-exists idempotency
            # Resend the fully-accepted message from 2b with more sigs
            kvy.processMsg(msg, **dict(ssgs=[(prefixer, allSigers)]))

            # kramit finds existing cache, multi-key path -> accumulation attempt
            # but threshold already met -> idempotent drop, no error
            cacheAfter = receiverHby.db.msgc.get(keys=(senderHab.pre, msg.said))
            assert cacheAfter is not None
            assert cacheAfter.mdt == cacheOrig.mdt

    """Done Test"""


def test_asr(mockHelpingNowUTC):
    """Test processMsg with seal-based auth (asr auth type).

    Covers: valid seal via sscs, valid seal via ssts, non-matching ssts
    fallback to sig auth, invalid seal (no matching digest), missing KEL event.
    """

    # Step 1: Setup

    salt1 = core.Salter(raw=b'0123456789abcdef').qb64
    salt2 = core.Salter(raw=b'0123456789abcdeg').qb64

    with (habbing.openHby(name="sender", base="test", salt=salt1) as senderHby,
          habbing.openHby(name="receiver", base="test", salt=salt2) as receiverHby):

        # Create transferable single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1,
                                      transferable=True)
        # Create receiver hab for db context
        receiverHby.makeHab(name="receiver", isith='1', icount=1,
                            transferable=True)

        # Cross-feed sender ICP to receiver
        crossKvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        # Create Kramer + Kevery
        with configing.openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            prefixer = coring.Prefixer(qb64=senderHab.pre)


            # Step 2: Valid seal via sscs (pure seal path)

            # Build v2 qry message (need SAID for seal)
            # Each step uses a unique 'n' (nonce) to produce distinct SAIDs
            msg = eventing.query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre, n='3b'),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            # Anchor msg SAID in sender's KEL via interaction event
            ixnMsg = senderHab.interact(data=[dict(d=msg.said)])
            # Cross-feed ixn to receiver
            parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            # Build sscs referencing the ixn event
            ixnSn = senderHab.kever.sn
            ixnSaid = senderHab.kever.serder.said
            sscs = [(coring.Seqner(sn=ixnSn), coring.Saider(qb64=ixnSaid))]

            # Pure seal, no sigs. kramit accepts via asr, but downstream
            # _processMsgQry raises ValidationError (no source/cigars).
            with pytest.raises(kering.ValidationError):
                kvy.processMsg(msg, **dict(sscs=sscs))

            # Assert: kramit created cache before downstream error
            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.ml == 5000  # short lag (asr)

            kvy.cues.clear()


            # Step 3: Test Valid seal via ssts + ssgs for downstream

            msg2 = eventing.query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3c'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Anchor in new ixn
            ixnMsg = senderHab.interact(data=[dict(d=msg2.said)])
            parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            ixnSn = senderHab.kever.sn
            ixnSaid = senderHab.kever.serder.said

            # Build ssts (sender-matching triple)
            ssts = [(coring.Prefixer(qb64=senderHab.pre),
                     coring.Seqner(sn=ixnSn),
                     coring.Saider(qb64=ixnSaid))]

            # Also provide ssgs for downstream dispatch
            sigers = senderHab.mgr.sign(ser=msg2.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssts=ssts, ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg2, **kwa)

            # Assert accepted via asr, full flow succeeds
            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg2.said))
            assert cache is not None
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"
            kvy.cues.clear()


            # Step 4: Test Non-matching ssts falls back to assk

            msg3 = eventing.query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3d'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Build ssts with a DIFFERENT prefixer (not sender)
            otherPre = "E" + "A" * 43  # fabricated AID
            nonMatchingSsts = [(coring.Prefixer(qb64=otherPre),
                                coring.Seqner(sn=ixnSn),
                                coring.Saider(qb64=ixnSaid))]

            # Also provide valid ssgs from actual sender
            sigers = senderHab.mgr.sign(ser=msg3.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssts=nonMatchingSsts, ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg3, **kwa)

            # Resolves to assk (single-key). Accepted via sig auth.
            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg3.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (assk, same as sl)

            kvy.cues.clear()


            # Step 5: Test invalid seal, event exists but no matching digest

            msg4 = eventing.query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3e'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference sender's icp (sn=0) icp has no seals matching msg4.said
            icpDig = receiverHby.db.kels.getOnLast(keys=senderHab.pre.encode(), on=0)

            sscs = [(coring.Seqner(sn=0), coring.Saider(qb64=icpDig))]
            kwa = dict(sscs=sscs)  # pure sscs, no sigs

            # kramit returns None (message dropped)
            kvy.processMsg(msg4, **kwa)

            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg4.said))
            assert cache is None  # no cache created

            kvy.cues.clear()


            # Step 6: Test missing KEL event

            msg5 = eventing.query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3f'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference sn=999 (event doesn't exist in receiver's copy)
            sscs = [(coring.Seqner(sn=999), coring.Saider(qb64=ixnSaid))]
            kwa = dict(sscs=sscs)  # pure sscs, no sigs

            kvy.processMsg(msg5, **kwa)

            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg5.said))
            assert cache is None  # no cache

            kvy.cues.clear()


            # Step 7: Missing KEL with sscs + ssgs falls back to sig auth

            msg6 = eventing.query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3f2'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            sscs = [(coring.Seqner(sn=999), coring.Saider(qb64=ixnSaid))]
            sigers = senderHab.mgr.sign(ser=msg6.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(prefixer, sigers)])

            # falls back to assk
            kvy.processMsg(msg6, **kwa)

            cache = receiverHby.db.msgc.get(keys=(senderHab.pre, msg6.said))
            assert cache is not None  # accepted via sig fallback
            assert cache.ml == 5000  # short lag (assk)

    """Done Test"""

def test_both_attached(mockHelpingNowUTC):
    """Test processMsg with both seal refs and sigs present.

    Tests _resolveAuthType fallback logic:
    - valid seal + valid sigs -> resolves to asr
    - invalid seal + valid sigs (single-key) -> falls back to assk
    - invalid seal + valid sigs (multi-key) -> falls back to asmk
    - valid seal + invalid sigs -> resolves to asr (sigs irrelevant)
    """

    # Step 1: Setup

    salt1 = core.Salter(raw=b'0123456789abcdef').qb64
    salt2 = core.Salter(raw=b'0123456789abcdeg').qb64
    salt3 = core.Salter(raw=b'0123456789abcdeh').qb64

    with (habbing.openHby(name="sender", base="test", salt=salt1) as skHby,
          habbing.openHby(name="mkSender", base="test", salt=salt2) as mkHby,
          habbing.openHby(name="receiver", base="test", salt=salt3) as receiverHby):

        # Create single-key sender
        skHab = skHby.makeHab(name="sender", isith='1', icount=1,
                              transferable=True)
        # Create multi-key sender (2-of-3)
        mkHab = mkHby.makeHab(name="mkSender", isith='2', icount=3,
                              transferable=True)
        # Create receiver hab for db context
        receiverHby.makeHab(name="receiver", isith='1', icount=1,
                            transferable=True)

        # Cross-feed both senders to receiver
        crossKvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False)

        skIcp = skHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(skIcp), kvy=crossKvy)
        assert skHab.pre in crossKvy.kevers

        mkIcp = mkHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(mkIcp), kvy=crossKvy)
        assert mkHab.pre in crossKvy.kevers

        # Create Kramer + Kevery
        with configing.openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            skPrefixer = coring.Prefixer(qb64=skHab.pre)
            mkPrefixer = coring.Prefixer(qb64=mkHab.pre)


            # Step 2: Valid seal + valid sigs (single-key) resolves to asr

            msg = eventing.query(pre=skHab.pre,
                                 route="ksn",
                                 query=dict(i=skHab.pre, src=skHab.pre, n='4b'),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            # Anchor SAID in sender's KEL
            ixnMsg = skHab.interact(data=[dict(d=msg.said)])
            parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            ixnSn = skHab.kever.sn
            ixnSaid = skHab.kever.serder.said
            sscs = [(coring.Seqner(sn=ixnSn), coring.Saider(qb64=ixnSaid))]

            # Valid sigs too
            sigers = skHab.mgr.sign(ser=msg.raw,
                                    verfers=skHab.kever.verfers,
                                    indexed=True)

            kwa = dict(sscs=sscs, ssgs=[(skPrefixer, sigers)])
            kvy.processMsg(msg, **kwa)

            # Assert: accepted via asr (seal takes priority), short lag
            cache = receiverHby.db.msgc.get(keys=(skHab.pre, msg.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (asr)

            kvy.cues.clear()


            # Step 3: Invalid seal + valid sigs (single-key) falls back to assk

            msg2 = eventing.query(pre=skHab.pre,
                                  route="ksn",
                                  query=dict(i=skHab.pre, src=skHab.pre, n='4c'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference icp (sn=0), no seal for this msg
            icpDig = receiverHby.db.kels.getOnLast(keys=skHab.pre.encode(), on=0)
            sscs = [(coring.Seqner(sn=0), coring.Saider(qb64=icpDig))]

            sigers = skHab.mgr.sign(ser=msg2.raw,
                                    verfers=skHab.kever.verfers,
                                    indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(skPrefixer, sigers)])

            kvy.processMsg(msg2, **kwa)

            # _resolveAuthType: seal fails -> single-key resolves to assk
            cache = receiverHby.db.msgc.get(keys=(skHab.pre, msg2.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (assk)

            kvy.cues.clear()


            # Step 4: Invalid seal + valid sigs (multi-key) falls back to asmk

            msg3 = eventing.query(pre=mkHab.pre,
                                  route="ksn",
                                  query=dict(i=mkHab.pre, src=mkHab.pre, n='4d'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference mk sender's icp (sn=0), no seal for this msg
            mkIcpDig = receiverHby.db.kels.getOnLast(keys=mkHab.pre.encode(), on=0)
            sscs = [(coring.Seqner(sn=0), coring.Saider(qb64=mkIcpDig))]

            # Partial sigs (1 of 3)
            allSigers = mkHab.mgr.sign(ser=msg3.raw,
                                       verfers=mkHab.kever.verfers,
                                       indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(mkPrefixer, [allSigers[0]])])

            kvy.processMsg(msg3, **kwa)

            # _resolveAuthType: seal fails, resolves to asmk
            cache = receiverHby.db.msgc.get(keys=(mkHab.pre, msg3.said))
            assert cache is not None
            assert cache.ml == 60000  # long lag (asmk)
            # Partials populated, threshold not met
            assert receiverHby.db.pmkm.get(keys=(mkHab.pre, msg3.said)) is not None
            pmks = receiverHby.db.pmks.get(keys=(mkHab.pre, msg3.said))
            assert len(pmks) == 1

            # Send 2nd sig -> threshold met (2 of 3)
            kvy.processMsg(msg3, **dict(sscs=sscs,
                                        ssgs=[(mkPrefixer, [allSigers[1]])]))

            # Partials cleaned up
            assert receiverHby.db.pmkm.get(keys=(mkHab.pre, msg3.said)) is None
            assert receiverHby.db.pmks.get(keys=(mkHab.pre, msg3.said)) == []

            kvy.cues.clear()


            # Step 5: Valid seal + invalid sigs resolves to asr (sigs irrelevant)

            msg4 = eventing.query(pre=skHab.pre,
                                  route="ksn",
                                  query=dict(i=skHab.pre, src=skHab.pre, n='4e'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Anchor SAID in sender's KEL
            ixnMsg = skHab.interact(data=[dict(d=msg4.said)])
            parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            ixnSn = skHab.kever.sn
            ixnSaid = skHab.kever.serder.said
            sscs = [(coring.Seqner(sn=ixnSn), coring.Saider(qb64=ixnSaid))]

            # Create wrong sigs (sign different data)
            wrongSigers = skHab.mgr.sign(ser=b'wrong data to sign',
                                         verfers=skHab.kever.verfers,
                                         indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(skPrefixer, wrongSigers)])

            kvy.processMsg(msg4, **kwa)

            # _resolveAuthType: seal validates -> asr -> sigs never checked
            cache = receiverHby.db.msgc.get(keys=(skHab.pre, msg4.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (asr)

    """Done Test"""


def test_transactioned(mockHelpingNowUTC):
    """Test processMsg with transactioned messages (xip/exn, tmsc cache).

    Covers: seed xip via kramit directly, exn via processMsg, missing xip
    cache, exchange window test, multi-key accumulation in transactioned path.
    """

    # Step 1: Setup

    salt1 = core.Salter(raw=b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu').qb64
    salt2 = core.Salter(raw=b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hv').qb64
    salt3 = core.Salter(raw=b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hw').qb64

    with (habbing.openHby(name="sender", base="test", salt=salt1) as skHby,
          habbing.openHby(name="mkSender", base="test", salt=salt2) as mkHby,
          habbing.openHby(name="receiver", base="test", salt=salt3) as receiverHby):

        # Create single-key sender
        skHab = skHby.makeHab(name="sender", isith='1', icount=1,
                              transferable=True)
        # Create multi-key sender (2-of-3) for step 7
        mkHab = mkHby.makeHab(name="mkSender", isith='2', icount=3,
                              transferable=True)
        # Create receiver hab for db context
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1,
                                          transferable=True)

        # Cross-feed both senders to receiver
        crossKvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False)

        skIcp = skHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(skIcp), kvy=crossKvy)
        assert skHab.pre in crossKvy.kevers

        mkIcp = mkHab.makeOwnEvent(sn=0)
        parsing.Parser(version=Vrsn_1_0).parse(ims=bytearray(mkIcp), kvy=crossKvy)
        assert mkHab.pre in crossKvy.kevers

        # Create Kramer + Kevery
        with configing.openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = eventing.Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            skPrefixer = coring.Prefixer(qb64=skHab.pre)
            mkPrefixer = coring.Prefixer(qb64=mkHab.pre)


            # Step 2: Test with seeded xip via kramit directly

            xip = eventing.exchept(sender=skHab.pre,
                                   receiver=receiverHab.pre,
                                   route="/test/exchange",
                                   stamp=stamp)

            # Sign xip
            sigers = skHab.mgr.sign(ser=xip.raw,
                                    verfers=skHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            # Call kramit directly (processMsg rejects xip)
            result = kramer.kramit(xip, **kwa)
            assert result is not None  # xip accepted

            # Assert: tmsc entry created, xip's exId is its own SAID
            cache = receiverHby.db.tmsc.get(keys=(skHab.pre, xip.said, xip.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.xdt == stamp  # xip's xdt == its own dt


            # Step 3: exn with exchange ID via processMsg

            exn = eventing.exchange(sender=skHab.pre,
                                    receiver=receiverHab.pre,
                                    xid=xip.said,
                                    route="/test/exchange",
                                    attributes=dict(n='5c'),
                                    stamp=stamp)

            sigers = skHab.mgr.sign(ser=exn.raw,
                                    verfers=skHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            # Error raised due to lack of exchanger. Could probably set one up for this test
            with pytest.raises(kering.ValidationError):
                kvy.processMsg(exn, **kwa)

            # Assert tmsc entry created for exn
            cache = receiverHby.db.tmsc.get(keys=(skHab.pre, xip.said, exn.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.xdt == stamp  # inherited from xip's xdt


            # Step 4: Missing xip cache

            fakeXid = "E" + "B" * 43  # fabricated xip SAID with no tmsc entry
            msg3 = eventing.exchange(sender=skHab.pre,
                                     receiver=receiverHab.pre,
                                     xid=fakeXid,
                                     route="/test/exchange",
                                     attributes=dict(n='5d'),
                                     stamp=stamp)

            sigers = skHab.mgr.sign(ser=msg3.raw,
                                    verfers=skHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            # kramit can't find xip's xdt, returns None, processMsg returns
            kvy.processMsg(msg3, **kwa)

            # Assert no tmsc entry for the exn
            cache = receiverHby.db.tmsc.get(keys=(skHab.pre, fakeXid, msg3.said))
            assert cache is None


            # Step 5: Exchange window test

            # Seed a tmsc entry with an old xdt directly in the database
            # so the exn's mdt (now) is outside the exchange window
            # xl=300000ms = 5min. xdt = 10min ago -> now > xdt + 5min
            oldXdt = "2020-12-31T23:50:00.000000+00:00"  # 10 min before mocked now
            oldXipSaid = "E" + "C" * 43  # fabricated xip SAID for this test
            seedRecord = basing.TxnMsgCacheRecord(
                mdt=oldXdt, xdt=oldXdt, d=1000, ml=5000, pml=5000,
                xl=300000, pxl=300000)
            receiverHby.db.tmsc.pin(keys=(skHab.pre, oldXipSaid, oldXipSaid),
                                    val=seedRecord)

            msg4 = eventing.exchange(sender=skHab.pre,
                                     receiver=receiverHab.pre,
                                     xid=oldXipSaid,
                                     route="/test/exchange",
                                     attributes=dict(n='5e'),
                                     stamp=stamp)

            sigers = skHab.mgr.sign(ser=msg4.raw,
                                    verfers=skHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            # mdt passes standard timeliness, but
            # xdt=10min ago, mdt=now: xdt + xl = 5min ago < now -> fails
            kvy.processMsg(msg4, **kwa)

            # Assert no tmsc entry (exchange window failed)
            cache = receiverHby.db.tmsc.get(
                keys=(skHab.pre, oldXipSaid, msg4.said))
            assert cache is None


            # Step 6: Seed xip for multi-key sender

            mkXip = eventing.exchept(sender=mkHab.pre,
                                     receiver=receiverHab.pre,
                                     route="/test/exchange",
                                     stamp=stamp)

            sigers = mkHab.mgr.sign(ser=mkXip.raw,
                                    verfers=mkHab.kever.verfers,
                                    indexed=True)
            # Use all sigs for xip to seed it successfully
            result = kramer.kramit(mkXip, **dict(ssgs=[(mkPrefixer, sigers)]))
            assert result is not None

            cache = receiverHby.db.tmsc.get(
                keys=(mkHab.pre, mkXip.said, mkXip.said))
            assert cache is not None


            # Step 7: Multi-key accumulation in transactioned path

            mkExn = eventing.exchange(sender=mkHab.pre,
                                      receiver=receiverHab.pre,
                                      xid=mkXip.said,
                                      route="/test/exchange",
                                      attributes=dict(n='5f'),
                                      stamp=stamp)

            allSigers = mkHab.mgr.sign(ser=mkExn.raw,
                                       verfers=mkHab.kever.verfers,
                                       indexed=True)

            # First delivery: 1 sig (below 2-of-3 threshold)
            kwa = dict(ssgs=[(mkPrefixer, [allSigers[0]])])
            # kramit returns None (pending) -> processMsg returns without dispatch
            kvy.processMsg(mkExn, **kwa)

            # tmsc cache created (multi-key still creates cache entry)
            cache = receiverHby.db.tmsc.get(
                keys=(mkHab.pre, mkXip.said, mkExn.said))
            assert cache is not None

            # Partials populated (keyed by (AID, MID) per spec)
            partialKey = (mkHab.pre, mkExn.said)
            assert receiverHby.db.pmkm.get(keys=partialKey) is not None
            pmks = receiverHby.db.pmks.get(keys=partialKey)
            assert len(pmks) == 1

            # Second delivery: sig at index 2 -> 2 of 3 -> threshold met
            kwa = dict(ssgs=[(mkPrefixer, [allSigers[2]])])
            # kramit returns msg (threshold met). processMsg dispatches to
            # _processMsgExn which raises ValidationError (no Exchanger).
            with pytest.raises(kering.ValidationError):
                kvy.processMsg(mkExn, **kwa)

            # Partials cleaned up
            assert receiverHby.db.pmkm.get(keys=partialKey) is None
            assert receiverHby.db.pmks.get(keys=partialKey) == []

    """Done Test"""