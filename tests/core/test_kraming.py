# -*- encoding: utf-8 -*-
"""tests.core.test_kraming module

Tests for KRAM (KERI Request Authentication Mechanism) integration through
processMsg on Kevery.
"""

import pytest

from hio.base import doing


from keri.kering import (KramConfigurationError, MissingAuthAttachmentError,
                         MissingSenderKeyStateError, ValidationError,
                         Protocols, Kinds, Ilks, Vrsn_1_0, Vrsn_2_0, versify)

from keri.core import (Kramer, SerderKERI, Kevery, Pruner, Salter,
                       Parser, Seqner, Saider, Prefixer, Diger,
                       Dater, Noncer, Number, Verser, Labeler, Texter,
                       AuthTypes, exchange, exchept, reply, query)

from keri.app import openHby, openCF
from keri.db import openDB
from keri.peer import Exchanger
from keri.recording import TxnMsgCacheRecord
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

    with openCF(name="kram", base="test") as cf:
        cf.put(validCf)
        with openDB(name="test_config", temp=True) as db:
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
            rec = db.kramCTYP.get("~")
            assert rec is not None
            assert rec.d == 100
            assert rec.sl == 2000
            assert rec.ll == 7200000
            assert rec.xl == 172800000
            assert rec.psl == 2000
            assert rec.pll == 7200000
            assert rec.pxl == 172800000

            # qry cache type
            rec = db.kramCTYP.get("qry")
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

    with openCF(name="kram", base="test") as cf:
        cf.put(emptyCf)
        with openDB(name="test_config_empty", temp=True) as db:
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

    with openCF(name="kram", base="test") as cf:
        cf.put(badStructCf)
        with openDB(name="test_config_bad_struct", temp=True) as db:
            with pytest.raises(KramConfigurationError):
                Kramer(db, cf)

    # Error path: malformed denial (too many elements in version)

    badVersionCf = {
        "kram": {
            "enabled": True,
            "denials": [[1, 2, 3]],
            "caches": {},
        }
    }

    with openCF(name="kram", base="test") as cf:
        cf.put(badVersionCf)
        with openDB(name="test_config_bad_version", temp=True) as db:
            with pytest.raises(KramConfigurationError):
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

    with openCF(name="kram", base="test") as cf:
        cf.put(badCacheCf)
        with openDB(name="test_config_bad_cache", temp=True) as db:
            with pytest.raises(KramConfigurationError):
                Kramer(db, cf)


def test_cache_type_constraints_valid():
    """Kramer init succeeds when cache-type tuple satisfies spec constraints."""
    validCf = {
        "kram": {
            "enabled": False,
            "denials": [],
            "caches": {
                "~": [100, 2000, 7200000, 172800000, 2000, 7200000, 172800000],
            },
        }
    }
    with openCF(name="kram", base="test") as cf:
        cf.put(validCf)
        with openDB(name="test_config_constraints_valid", temp=True) as db:
            Kramer(db, cf)
            rec = db.kramCTYP.get("~")
            assert rec is not None
            assert rec.d == 100
            assert rec.sl == 2000
            assert rec.ll == 7200000
            assert rec.xl == 172800000
            assert rec.psl == 2000
            assert rec.pll == 7200000
            assert rec.pxl == 172800000


@pytest.mark.parametrize(
    "caches",
    [
        pytest.param({"~": [-1, 2000, 7200000, 172800000, 2000, 7200000, 172800000]}, id="d_negative"),
        pytest.param({"~": [100, 8000000, 2000, 172800000, 2000, 7200000, 172800000]}, id="sl_ll_xl_order"),
        pytest.param({"~": [100, 2000, 7200000, 172800000, 1000, 7200000, 172800000]}, id="psl_sl"),
        pytest.param({"~": [100, 2000, 7200000, 172800000, 2000, 5000000, 172800000]}, id="pll_ll"),
        pytest.param({"~": [100, 2000, 7200000, 172800000, 2000, 7200000, 100000000]}, id="pxl_xl"),
    ],
)
def test_cache_type_constraints_invalid(request, caches):
    """
    Tests the behavior of cache type constraints within the Kramer configuration.

    This parameterized test suite is designed to validate that invalid combinations of cache
    parameters raise the appropriate `KramConfigurationError` based on KRAM spec which requires 
    the following constraints:
    0 <= d
    0 < sl <= ll <= xl
    0 < sl <= psl
    0 < ll <= pll
    0 < xl <= pxl
    """
    cfg = {
        "kram": {
            "enabled": False,
            "denials": [],
            "caches": caches,
        }
    }
    db_name = f"test_cache_ctyp_{request.node.callspec.id}"
    with openCF(name="kram", base="test") as cf:
        cf.put(cfg)
        with openDB(name=db_name, temp=True) as db:
            with pytest.raises(KramConfigurationError):
                Kramer(db, cf)


def test_change_config_rejects_invalid_cache_constraints():
    """Kramer.changeConfig raises when new cache tuple violates constraints."""
    old_cfg = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [100, 2000, 3000, 4000, 2000, 3000, 4000],
            }
        }
    }

    # Invalid: sl <= 0 and ordering violation
    bad_cfg = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [100, 0, 3000, 4000, 2000, 3000, 4000],
            }
        }
    }

    with openCF(name="kram", base="test", temp=True) as cf:
        cf.put(old_cfg)
        with openDB(name="test_change_config_rejects_invalid", temp=True) as db:
            kramer = Kramer(db, cf)
            rec_before = db.kramCTYP.get("~")
            assert rec_before.sl == 2000

            cf.put(bad_cfg)
            with pytest.raises(KramConfigurationError):
                kramer.changeConfig(cf)

            # Existing config/cache record remains unchanged after failed update
            rec_after = db.kramCTYP.get("~")
            assert rec_after.sl == 2000
            assert kramer._kramCTYPCf == old_cfg["kram"]["caches"]


_testSigner = Salter(raw=b'0123456789abcdef').signer(transferable=True)
TEST_PRE = _testSigner.verfer.qb64


def test_intake():
    """Test intake routes messages through denial, passthrough, and kramit logic"""

    v1b64 = Verser.verToB64(major=1, minor=0)
    v2b64 = Verser.verToB64(major=2, minor=0)

    # --- Denial string generation ---

    # v2 reply with route
    serder = reply(
        pre=TEST_PRE,
        route="/end/role/add",
        data=dict(name="test"),
        pvrsn=Vrsn_2_0,
    )
    assert Kramer.denial(serder) == f"{v2b64}.rpy./end/role/add"

    # v1 query
    serder = query(
        route="/logs",
        query=dict(stuff="hello"),
        pvrsn=Vrsn_1_0,
    )
    assert Kramer.denial(serder) == f"{v1b64}.qry./logs"

    # empty route
    serder = reply(
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

    with openCF(name="kram_intake", base="test") as cf:
        cf.put(disabledCf)
        with openDB(name="test_intake_dis", temp=True) as db:
            kramer = Kramer(db, cf)
            serder = reply(pre=TEST_PRE, route="/test",
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

    with openCF(name="kram_intake", base="test") as cf:
        cf.put(enabledCf)
        with openDB(name="test_intake_den", temp=True) as db:
            kramer = Kramer(db, cf)

            # v2 rpy /end/role/add matches denial for rpy + /end
            serder = reply(
                pre=TEST_PRE,
                route="/end/role/add",
                data=dict(a=1),
                pvrsn=Vrsn_2_0,
            )
            result = kramer.intake(serder)
            assert result is serder  # denied from KRAM, passed through

            # v1 message matches blanket v1 denial
            serder = reply(
                route="/something",
                data=dict(a=1),
                pvrsn=Vrsn_1_0,
            )
            result = kramer.intake(serder)
            assert result is serder  # denied from KRAM, passed through

            # v2 qry does NOT match any denial — should reach kramit
            serder = query(
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

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64
    salt3 = Salter(raw=b'0123456789abcdeh').qb64
    salt4 = Salter(raw=b'0123456789abcdei').qb64

    with (openHby(name="sender", base="test", salt=salt1) as senderHby,
          openHby(name="senderNT", base="test", salt=salt2) as senderNTHby,
          openHby(name="receiver", base="test", salt=salt3) as receiverHby,
          openHby(name="unknown", base="test", salt=salt4) as unknownHby):

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
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        senderNTIcp = senderNTHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderNTIcp), kvy=crossKvy)
        assert senderNTHab.pre in crossKvy.kevers

        # Create Kramer with config
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            assert kramer.enabled

            # Create Kevery with kramer for KRAM testing
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)


            # Step 2: ssgs happy path

            # Build v2 qry message with mocked timestamp
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.d == 1000   # drift from config
            assert cache.ml == 5000  # short lag (assk)

            # Assert downstream processQuery generated a "reply" cue
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"


            # Step 3: cigars happy path (non-transferable sender)

            msg2 = query(pre=senderNTHab.pre,
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
            cache = receiverHby.db.kramMSGC.get(keys=(senderNTHab.pre, msg2.said))
            assert cache is not None
            assert cache.mdt == stamp


            # Step 4: Test timeliness against stale message

            # Build qry with timestamp far outside acceptance window
            staleStamp = "2020-01-01T00:00:00.000000+00:00"
            staleMsg = query(pre=senderHab.pre,
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
            staleCache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, staleMsg.said))
            assert staleCache is None


            # Step 5: Test cache idempotency

            # Resend the same message + kwa from step 2
            # kramit finds existing cache -> returns None (assk idempotent drop)
            origCache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert origCache is not None  # still there from step 2

            kvy.processMsg(msg, **dict(ssgs=[(prefixer, sigers)]))

            # Cache entry unchanged, no error raised
            cacheAfter = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cacheAfter is not None
            assert cacheAfter.mdt == origCache.mdt


            # Step 6. Trigger MissingAuthAttachmentError

            noAuthMsg = query(pre=senderHab.pre,
                                       route="ksn",
                                       query=dict(i=senderHab.pre, src=senderHab.pre),
                                       stamp=stamp,
                                       pvrsn=Vrsn_2_0)

            with pytest.raises(MissingAuthAttachmentError):
                kvy.processMsg(noAuthMsg)  # empty kwa — no auth attachments

            # Clear the cues
            kvy.cues.clear()


            # Step 7: Trigger MissingSenderKeyStateError

            # Build qry from unknown sender
            unknownMsg = query(pre=unknownHab.pre,
                                        route="ksn",
                                        query=dict(i=unknownHab.pre, src=unknownHab.pre),
                                        stamp=stamp,
                                        pvrsn=Vrsn_2_0)

            unknownSigers = unknownHab.mgr.sign(ser=unknownMsg.raw,
                                                verfers=unknownHab.kever.verfers,
                                                indexed=True)
            unknownPrefixer = Prefixer(qb64=unknownHab.pre)
            unknownKwa = dict(ssgs=[(unknownPrefixer, unknownSigers)])

            with pytest.raises(MissingSenderKeyStateError):
                kvy.processMsg(unknownMsg, **unknownKwa)

            # Assert cue key state retrieval notification
            cue = kvy.cues.popleft()
            assert cue['kin'] == 'keystate'
            assert cue['aid'] == unknownHab.pre
            assert cue['sn'] is None

    """Done Test"""


def test_asmk(mockHelpingNowUTC):
    """Test processMsg with multi-key sender (asmk auth type, 2-of-3 threshold).

    Covers: full sigs immediate threshold, partial accumulation then threshold,
    duplicate sig dedup, mixed sig sources (ssgs+tsgs), key state change during
    accumulation, long lag timeliness, cache-exists idempotency.
    """

    # Step 1: Setup

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="mkSender", base="test", salt=salt1) as senderHby,
          openHby(name="mkReceiver", base="test", salt=salt2) as receiverHby):

        # Create 2-of-3 multi-key sender
        senderHab = senderHby.makeHab(name="mkSender", isith='2', icount=3,
                                      transferable=True)
        assert len(senderHab.kever.verfers) == 3

        # Create receiver hab for db context
        receiverHby.makeHab(name="mkReceiver", isith='1', icount=1,
                            transferable=True)

        # Cross-feed sender ICP to receiver
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        # Create Kevery with kramer
        with openCF(name="mkKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)
            verfers = senderHab.kever.verfers

            # Sign all 3 keys once, select subsets per test step
            def signMsg(msg):
                return senderHab.mgr.sign(ser=msg.raw, verfers=verfers,
                                          indexed=True)


            # Step 2: Test full sigs immediately meeting threshold

            msg = query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp,
                                   pvrsn=Vrsn_2_0)
            allSigers = signMsg(msg)
            assert len(allSigers) == 3

            kwa = dict(ssgs=[(prefixer, allSigers)])
            kvy.processMsg(msg, **kwa)

            # Assert kramMSGC cache created, partials empty (threshold met immediately)
            cacheOrig = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cacheOrig is not None
            assert cacheOrig.ml == 60000  # long lag (asmk)
            assert receiverHby.db.kramPMKM.get(keys=(senderHab.pre, msg.said)) is None
            assert receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg.said)) == []
            assert receiverHby.db.kramPMSK.get(keys=(senderHab.pre, msg.said)) is None

            kvy.cues.clear()


            # Step 3: Partial accumulation

            # First delivery, 1 sig (below 2-of-3 threshold)
            # Distinct stamp so msg2.said != msg.said (partials from step 2 don't collide)
            stamp2 = "2020-12-31T23:59:59.000000+00:00"
            msg2 = query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp2,
                                   pvrsn=Vrsn_2_0)
            allSigers2 = signMsg(msg2)

            kwa = dict(ssgs=[(prefixer, [allSigers2[0]])])
            kvy.processMsg(msg2, **kwa)

            # Assert kramMSGC cache created for partial sigs
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg2.said))
            assert cache is not None

            # Assert that partial DBs are populated
            kramPMKM = receiverHby.db.kramPMKM.get(keys=(senderHab.pre, msg2.said))
            assert kramPMKM is not None
            kramPMKS = receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg2.said))
            assert kramPMKS is not None
            assert len(kramPMKS) == 1
            kramPMSK = receiverHby.db.kramPMSK.get(keys=(senderHab.pre, msg2.said))
            assert kramPMSK is not None

            # No cue generated because threshold not met
            assert len(kvy.cues) == 0

            # Second delivery: 2 of 3 sigs, threshold met
            kwa = dict(ssgs=[(prefixer, [allSigers2[2]])])
            kvy.processMsg(msg2, **kwa)

            # Partials persist until pruner cleans up (not deleted on threshold)
            assert receiverHby.db.kramPMKM.get(keys=(senderHab.pre, msg2.said)) is not None
            kramPMKS = receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg2.said))
            assert len(kramPMKS) >= 2
            assert receiverHby.db.kramPMSK.get(keys=(senderHab.pre, msg2.said)) is not None

            # Assert that downstream dispatch occurred via cue gen
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"
            kvy.cues.clear()


            # Step 4: Test duplicate sig does not double-count

            msg3 = query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp="2020-12-31T23:59:58.000000+00:00",
                                   pvrsn=Vrsn_2_0)
            allSigers3 = signMsg(msg3)

            # First delivery, sig index 0
            kvy.processMsg(msg3, **dict(ssgs=[(prefixer, [allSigers3[0]])]))
            kramPMKS = receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg3.said))
            assert len(kramPMKS) == 1

            # Second delivery: same sig index 0 again
            kvy.processMsg(msg3, **dict(ssgs=[(prefixer, [allSigers3[0]])]))
            kramPMKS_after = receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg3.said))
            assert len(kramPMKS_after) == 1  # deduped, still 1 unique sig

            kvy.cues.clear()


            # Step 5: Test mixed sig sources, ssgs + tsgs in same kwa

            msg4 = query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp="2020-12-31T23:59:57.000000+00:00",
                                   pvrsn=Vrsn_2_0)
            allSigers4 = signMsg(msg4)

            # Get sender's current key state for tsgs
            senderKever = receiverHby.db.kevers[senderHab.pre]
            seqner = Seqner(sn=senderKever.sner.num)
            saider = Saider(qb64=senderKever.serder.said)

            # ssgs with sig index 0, tsgs with sig index 1
            tsg = (prefixer, seqner, saider, [allSigers4[1]])
            kwa = dict(ssgs=[(prefixer, [allSigers4[0]])],
                         tsgs=[tsg])

            kvy.processMsg(msg4, **kwa)

            # Assert both sigs pooled, 2 of 3 threshold met
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg4.said))
            assert cache is not None
            # Partials persist until pruner cleans up (not deleted on threshold)
            assert receiverHby.db.kramPMKM.get(keys=(senderHab.pre, msg4.said)) is None

            kvy.cues.clear()


            # Step 6: Key state change during accumulation

            msg5 = query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp="2020-12-31T23:59:56.000000+00:00",
                                   pvrsn=Vrsn_2_0)
            allSigers2f = signMsg(msg5)

            # First delivery, 1 sig
            kvy.processMsg(msg5, **dict(ssgs=[(prefixer, [allSigers2f[0]])]))
            assert receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg5.said)) is not None

            # Rotate sender
            rotMsg = senderHab.rotate()
            Parser(version=Vrsn_1_0).parse(ims=bytearray(rotMsg), kvy=crossKvy)

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
            msg6 = query(pre=senderHab.pre,
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
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg6.said))
            assert cache is not None
            assert cache.ml == 60000  # confirms long lag used

            kvy.cues.clear()

            # Step 8: Test cache-exists idempotency
            # Resend the fully-accepted message from 2b with more sigs
            kvy.processMsg(msg, **dict(ssgs=[(prefixer, allSigers)]))

            # kramit finds existing cache, multi-key path -> accumulation attempt
            # but threshold already met -> idempotent drop, no error
            cacheAfter = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cacheAfter is not None
            assert cacheAfter.mdt == cacheOrig.mdt

    """Done Test"""


def test_asr(mockHelpingNowUTC):
    """Test processMsg with seal-based auth (asr auth type).

    Covers: valid seal via sscs, valid seal via ssts, non-matching ssts
    fallback to sig auth, invalid seal (no matching digest), missing KEL event,
    missing KEL with sscs + ssgs falls back to assk, invalid seal + valid sigs
    (multi-key) falls back to asmk, valid seal + valid sigs (sscs) resolves to
    asr, invalid seal (wrong digest) + single-key sigs falls back to assk,
    valid seal + invalid sigs resolves to asr (sigs irrelevant).
    """

    # Step 1: Setup

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64
    salt3 = Salter(raw=b'0123456789abcdeh').qb64

    with (openHby(name="sender", base="test", salt=salt1) as senderHby,
          openHby(name="mkSender", base="test", salt=salt2) as mkHby,
          openHby(name="receiver", base="test", salt=salt3) as receiverHby):

        # Create transferable single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1,
                                      transferable=True)
        # Create multi-key sender (2-of-3)
        mkHab = mkHby.makeHab(name="mkSender", isith='2', icount=3,
                              transferable=True)
        # Create receiver hab for db context
        receiverHby.makeHab(name="receiver", isith='1', icount=1,
                            transferable=True)

        # Cross-feed both senders to receiver
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        mkIcp = mkHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(mkIcp), kvy=crossKvy)
        assert mkHab.pre in crossKvy.kevers

        # Create Kramer + Kevery
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)
            mkPrefixer = Prefixer(qb64=mkHab.pre)


            # Step 2: Valid seal via sscs (pure seal path)

            # Build v2 qry message (need SAID for seal)
            # Each step uses a unique 'n' (nonce) to produce distinct SAIDs
            msg = query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre, n='3b'),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            # Anchor msg SAID in sender's KEL via interaction event
            ixnMsg = senderHab.interact(data=[dict(d=msg.said)])
            # Cross-feed ixn to receiver
            Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            # Build sscs referencing the ixn event
            ixnSn = senderHab.kever.sn
            ixnSaid = senderHab.kever.serder.said
            sscs = [(Seqner(sn=ixnSn), Saider(qb64=ixnSaid))]

            # Pure seal, no sigs. kramit accepts via asr, but downstream
            # _processMsgQry raises ValidationError (no source/cigars).
            with pytest.raises(ValidationError):
                kvy.processMsg(msg, **dict(sscs=sscs))

            # Assert: kramit created cache before downstream error
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.ml == 5000  # short lag (asr)

            kvy.cues.clear()


            # Step 3: Test Valid seal via ssts + ssgs for downstream

            msg2 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3c'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Anchor in new ixn
            ixnMsg = senderHab.interact(data=[dict(d=msg2.said)])
            Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            ixnSn = senderHab.kever.sn
            ixnSaid = senderHab.kever.serder.said

            # Build ssts (sender-matching triple)
            ssts = [(Prefixer(qb64=senderHab.pre),
                     Seqner(sn=ixnSn),
                     Saider(qb64=ixnSaid))]

            # Also provide ssgs for downstream dispatch
            sigers = senderHab.mgr.sign(ser=msg2.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssts=ssts, ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg2, **kwa)

            # Assert accepted via asr, full flow succeeds
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg2.said))
            assert cache is not None
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"
            kvy.cues.clear()


            # Step 4: Test Non-matching ssts falls back to assk

            msg3 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3d'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Build ssts with a DIFFERENT prefixer (not sender)
            otherPre = "E" + "A" * 43  # fabricated AID
            nonMatchingSsts = [(Prefixer(qb64=otherPre),
                                Seqner(sn=ixnSn),
                                Saider(qb64=ixnSaid))]

            # Also provide valid ssgs from actual sender
            sigers = senderHab.mgr.sign(ser=msg3.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssts=nonMatchingSsts, ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg3, **kwa)

            # Resolves to assk (single-key). Accepted via sig auth.
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg3.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (assk, same as sl)

            kvy.cues.clear()


            # Step 5: Test invalid seal, event exists but no matching digest

            msg4 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3e'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference sender's icp (sn=0) icp has no seals matching msg4.said
            icpDig = receiverHby.db.kels.getLast(keys=senderHab.pre.encode(), on=0)

            sscs = [(Seqner(sn=0), Saider(qb64=icpDig))]
            kwa = dict(sscs=sscs)  # pure sscs, no sigs

            # kramit returns None (message dropped)
            kvy.processMsg(msg4, **kwa)

            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg4.said))
            assert cache is None  # no cache created

            kvy.cues.clear()


            # Step 6: Test missing KEL event

            msg5 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3f'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference sn=999 (event doesn't exist in receiver's copy)
            sscs = [(Seqner(sn=999), Saider(qb64=ixnSaid))]
            kwa = dict(sscs=sscs)  # pure sscs, no sigs

            kvy.processMsg(msg5, **kwa)

            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg5.said))
            assert cache is None  # no cache

            # Assert for cue key state retrieval
            cue = kvy.cues.popleft()
            assert cue['kin'] == "keystate"
            assert cue['aid'] == senderHab.pre
            assert cue['sn'] == 2

            kvy.cues.clear()


            # Step 7: Missing KEL with sscs + ssgs falls back to sig auth

            msg6 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='3f2'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            sscs = [(Seqner(sn=999), Saider(qb64=ixnSaid))]
            sigers = senderHab.mgr.sign(ser=msg6.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(prefixer, sigers)])

            # falls back to assk
            kvy.processMsg(msg6, **kwa)

            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg6.said))
            assert cache is not None  # accepted via sig fallback
            assert cache.ml == 5000  # short lag (assk)


            # Step 8: Valid seal (sscs) + valid sigs resolves to asr (seal takes priority)

            msg7 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='4b'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Anchor SAID in sender's KEL
            ixnMsg = senderHab.interact(data=[dict(d=msg7.said)])
            Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            ixnSn = senderHab.kever.sn
            ixnSaid = senderHab.kever.serder.said
            sscs = [(Seqner(sn=ixnSn), Saider(qb64=ixnSaid))]

            sigers = senderHab.mgr.sign(ser=msg7.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(prefixer, sigers)])
            kvy.processMsg(msg7, **kwa)

            # Seal valid -> asr, sigs irrelevant to auth type resolution
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg7.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (asr)

            kvy.cues.clear()


            # Step 9: Invalid seal (wrong digest) + valid sigs (single-key) falls back to assk

            msg8 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='4c'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference icp (sn=0) which has no seal for msg8 — seal invalid
            icpDig = receiverHby.db.kels.getLast(keys=senderHab.pre.encode(), on=0)
            sscs = [(Seqner(sn=0), Saider(qb64=icpDig))]

            sigers = senderHab.mgr.sign(ser=msg8.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(prefixer, sigers)])
            kvy.processMsg(msg8, **kwa)

            # _resolveAuthType: seal fails -> single-key resolves to assk
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg8.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (assk)

            kvy.cues.clear()


            # Step 10: Invalid seal + valid sigs (multi-key) falls back to asmk

            msg7 = query(pre=mkHab.pre,
                                  route="ksn",
                                  query=dict(i=mkHab.pre, src=mkHab.pre, n='4d'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Reference mk sender's icp (sn=0), no seal for this msg
            mkIcpDig = receiverHby.db.kels.getLast(keys=mkHab.pre.encode(), on=0)
            sscs = [(Seqner(sn=0), Saider(qb64=mkIcpDig))]

            # Partial sigs (1 of 3)
            allSigers = mkHab.mgr.sign(ser=msg7.raw,
                                       verfers=mkHab.kever.verfers,
                                       indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(mkPrefixer, [allSigers[0]])])

            kvy.processMsg(msg7, **kwa)

            # _resolveAuthType: seal fails, resolves to asmk
            cache = receiverHby.db.kramMSGC.get(keys=(mkHab.pre, msg7.said))
            assert cache is not None
            assert cache.ml == 60000  # long lag (asmk)
            # Partials populated, threshold not met
            assert receiverHby.db.kramPMKM.get(keys=(mkHab.pre, msg7.said)) is not None
            kramPMKS = receiverHby.db.kramPMKS.get(keys=(mkHab.pre, msg7.said))
            assert len(kramPMKS) == 1

            # Send 2nd sig -> threshold met (2 of 3)
            kvy.processMsg(msg7, **dict(sscs=sscs,
                                        ssgs=[(mkPrefixer, [allSigers[1]])]))

            # Partials persist until pruner cleans up (not deleted on threshold)
            assert receiverHby.db.kramPMKM.get(keys=(mkHab.pre, msg7.said)) is not None
            kramPMKS = receiverHby.db.kramPMKS.get(keys=(mkHab.pre, msg7.said))
            assert len(kramPMKS) >= 2

            kvy.cues.clear()


            # Step 11: Valid seal + invalid sigs resolves to asr (sigs irrelevant)

            msg8 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre, n='4e'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            # Anchor SAID in sender's KEL
            ixnMsg = senderHab.interact(data=[dict(d=msg8.said)])
            Parser(version=Vrsn_1_0).parse(ims=bytearray(ixnMsg), kvy=crossKvy)

            ixnSn = senderHab.kever.sn
            ixnSaid = senderHab.kever.serder.said
            sscs = [(Seqner(sn=ixnSn), Saider(qb64=ixnSaid))]

            # Create wrong sigs (sign different data)
            wrongSigers = senderHab.mgr.sign(ser=b'wrong data to sign',
                                             verfers=senderHab.kever.verfers,
                                             indexed=True)
            kwa = dict(sscs=sscs, ssgs=[(prefixer, wrongSigers)])

            kvy.processMsg(msg8, **kwa)

            # _resolveAuthType: seal validates -> asr -> sigs never checked
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg8.said))
            assert cache is not None
            assert cache.ml == 5000  # short lag (asr)

    """Done Test"""


def test_transactioned(mockHelpingNowUTC):
    """Test processMsg with transactioned messages (xip/exn, kramTMSC cache).

    Covers: seed xip via kramit directly, exn via processMsg, missing xip
    cache, exchange window test, multi-key accumulation in transactioned path.
    """

    # Step 1: Setup

    salt1 = Salter(raw=b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu').qb64
    salt2 = Salter(raw=b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hv').qb64
    salt3 = Salter(raw=b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hw').qb64

    with (openHby(name="sender", base="test", salt=salt1) as skHby,
          openHby(name="mkSender", base="test", salt=salt2) as mkHby,
          openHby(name="receiver", base="test", salt=salt3) as receiverHby):

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
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)

        skIcp = skHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(skIcp), kvy=crossKvy)
        assert skHab.pre in crossKvy.kevers

        mkIcp = mkHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(mkIcp), kvy=crossKvy)
        assert mkHab.pre in crossKvy.kevers

        # Create Kramer + Kevery
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            skPrefixer = Prefixer(qb64=skHab.pre)
            mkPrefixer = Prefixer(qb64=mkHab.pre)


            # Step 2: Test with seeded xip via kramit directly

            xip = exchept(sender=skHab.pre,
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

            # Assert: kramTMSC entry created, xip's exId is its own SAID
            cache = receiverHby.db.kramTMSC.get(keys=(skHab.pre, xip.said, xip.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.xdt == stamp  # xip's xdt == its own dt


            # Step 3: exn with exchange ID via processMsg

            exn = exchange(sender=skHab.pre,
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
            with pytest.raises(ValidationError):
                kvy.processMsg(exn, **kwa)

            # Assert kramTMSC entry created for exn
            cache = receiverHby.db.kramTMSC.get(keys=(skHab.pre, xip.said, exn.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.xdt == stamp  # inherited from xip's xdt


            # Step 4: Missing xip cache

            fakeXid = "E" + "B" * 43  # fabricated xip SAID with no kramTMSC entry
            msg3 = exchange(sender=skHab.pre,
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

            # Assert no kramTMSC entry for the exn
            cache = receiverHby.db.kramTMSC.get(keys=(skHab.pre, fakeXid, msg3.said))
            assert cache is None


            # Step 5: Exchange window test

            # Seed a kramTMSC entry with an old xdt directly in the database
            # so the exn's mdt (now) is outside the exchange window
            # xl=300000ms = 5min. xdt = 10min ago -> now > xdt + 5min
            oldXdt = "2020-12-31T23:50:00.000000+00:00"  # 10 min before mocked now
            oldXipSaid = "E" + "C" * 43  # fabricated xip SAID for this test
            seedRecord = TxnMsgCacheRecord(
                mdt=oldXdt, xdt=oldXdt, d=1000, ml=5000, pml=5000,
                xl=300000, pxl=300000)
            receiverHby.db.kramTMSC.pin(keys=(skHab.pre, oldXipSaid, oldXipSaid),
                                    val=seedRecord)

            msg4 = exchange(sender=skHab.pre,
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

            # Assert no kramTMSC entry (exchange window failed)
            cache = receiverHby.db.kramTMSC.get(
                keys=(skHab.pre, oldXipSaid, msg4.said))
            assert cache is None


            # Step 6: Seed xip for multi-key sender

            mkXip = exchept(sender=mkHab.pre,
                            receiver=receiverHab.pre,
                            route="/test/exchange",
                            stamp=stamp)

            sigers = mkHab.mgr.sign(ser=mkXip.raw,
                                    verfers=mkHab.kever.verfers,
                                    indexed=True)
            # Use all sigs for xip to seed it successfully
            result = kramer.kramit(mkXip, **dict(ssgs=[(mkPrefixer, sigers)]))
            assert result is not None

            cache = receiverHby.db.kramTMSC.get(
                keys=(mkHab.pre, mkXip.said, mkXip.said))
            assert cache is not None


            # Step 7: Multi-key accumulation in transactioned path

            mkExn = exchange(sender=mkHab.pre,
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

            # kramTMSC cache created (multi-key still creates cache entry)
            cache = receiverHby.db.kramTMSC.get(
                keys=(mkHab.pre, mkXip.said, mkExn.said))
            assert cache is not None

            # Partials populated (keyed by (AID, MID) per spec)
            partialKey = (mkHab.pre, mkExn.said)
            assert receiverHby.db.kramPMKM.get(keys=partialKey) is not None
            kramPMKS = receiverHby.db.kramPMKS.get(keys=partialKey)
            assert len(kramPMKS) == 1

            # Second delivery: sig at index 2 -> 2 of 3 -> threshold met
            kwa = dict(ssgs=[(mkPrefixer, [allSigers[2]])])
            # kramit returns msg (threshold met). processMsg dispatches to
            # _processMsgExn which raises ValidationError (no Exchanger).
            with pytest.raises(ValidationError):
                kvy.processMsg(mkExn, **kwa)

            # Partials persist until pruner cleans up (not deleted on threshold)
            assert receiverHby.db.kramPMKM.get(keys=partialKey) is not None
            kramPMKS = receiverHby.db.kramPMKS.get(keys=partialKey)
            assert len(kramPMKS) >= 2


            # Step 8: exc happy path

            exc = Exchanger(hby=receiverHby, handlers=[])
            kvyWithExc = Kevery(db=receiverHby.db, lax=False, local=False,
                                         kramer=kramer, exc=exc)
            assert kvyWithExc.exc is exc

            # Seed a fresh xip via kramit directly (processMsg rejects xip ilk)
            xip8 = exchept(sender=skHab.pre,
                           receiver=receiverHab.pre,
                           route="/test/exchange",
                           stamp=stamp)
            sigers8 = skHab.mgr.sign(ser=xip8.raw,
                                     verfers=skHab.kever.verfers,
                                     indexed=True)
            assert kramer.kramit(xip8, **dict(ssgs=[(skPrefixer, sigers8)])) is not None

            exn8 = exchange(sender=skHab.pre,
                            receiver=receiverHab.pre,
                            xid=xip8.said,
                            route="/test/exchange",
                            attributes=dict(n='5h'),
                            stamp=stamp)

            # Sign exn8 for both KRAM (ssgs) and downstream exn handler (tsgs)
            sigers8 = skHab.mgr.sign(ser=exn8.raw,
                                     verfers=skHab.kever.verfers,
                                     indexed=True)
            skKever = receiverHby.db.kevers[skHab.pre]
            tsg8 = (skPrefixer,
                    Seqner(sn=skKever.sner.num),
                    Saider(qb64=skKever.serder.said),
                    sigers8)

            kvyWithExc.processMsg(exn8,
                                  **dict(ssgs=[(skPrefixer, sigers8)],
                                         tsgs=[tsg8]))

            cache = receiverHby.db.kramTMSC.get(keys=(skHab.pre, xip8.said, exn8.said))
            assert cache is not None
            assert cache.mdt == stamp


            # Step 8: exc happy path

            exc = Exchanger(hby=receiverHby, handlers=[])
            kvyWithExc = Kevery(db=receiverHby.db, lax=False, local=False,
                                         kramer=kramer, exc=exc)
            assert kvyWithExc.exc is exc

            # Seed a fresh xip via kramit directly (processMsg rejects xip ilk)
            xip8 = exchept(sender=skHab.pre,
                           receiver=receiverHab.pre,
                           route="/test/exchange",
                           stamp=stamp)
            sigers8 = skHab.mgr.sign(ser=xip8.raw,
                                     verfers=skHab.kever.verfers,
                                     indexed=True)
            assert kramer.kramit(xip8, **dict(ssgs=[(skPrefixer, sigers8)])) is not None

            exn8 = exchange(sender=skHab.pre,
                            receiver=receiverHab.pre,
                            xid=xip8.said,
                            route="/test/exchange",
                            attributes=dict(n='5h'),
                            stamp=stamp)

            # Sign exn8 for both KRAM (ssgs) and downstream exn handler (tsgs)
            sigers8 = skHab.mgr.sign(ser=exn8.raw,
                                     verfers=skHab.kever.verfers,
                                     indexed=True)
            skKever = receiverHby.db.kevers[skHab.pre]
            tsg8 = (skPrefixer,
                    Seqner(sn=skKever.sner.num),
                    Saider(qb64=skKever.serder.said),
                    sigers8)

            kvyWithExc.processMsg(exn8,
                                  **dict(ssgs=[(skPrefixer, sigers8)],
                                         tsgs=[tsg8]))

            cache = receiverHby.db.kramTMSC.get(keys=(skHab.pre, xip8.said, exn8.said))
            assert cache is not None
            assert cache.mdt == stamp

    """Done Test"""


def test_v1_exn_non_transactioned(mockHelpingNowUTC):
    """Test that v1 exn messages are always routed as non-transactional.

    The v1 KERI exn message has no x field, so must be treated as
    non-transactioned from the standpoint of KRAM even when it has a
    non-empty prior p field value.

    Covers:
    - v1 exn with non-empty p field, no x field -> kramMSGC (non-txn) cache
    - v1 exn that carries an x field -> still kramMSGC, not kramTMSC (x ignored)
    - v2 exn with x field -> kramTMSC (transactional) cache, confirming the
      version gate does not break the v2 path
    """

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="v1exnSender", base="test", salt=salt1) as senderHby,
          openHby(name="v1exnReceiver", base="test", salt=salt2) as receiverHby):

        senderHab = senderHby.makeHab(name="v1exnSender", isith='1', icount=1,
                                      transferable=True)
        receiverHab = receiverHby.makeHab(name="v1exnReceiver", isith='1', icount=1,
                                          transferable=True)

        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        with openCF(name="v1exnKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            skPrefixer = Prefixer(qb64=senderHab.pre)

            stamp = helping.nowIso8601()


# Step 2: v1 exn with non-empty p field, no x field
            # The v1 exn schema rejects x/ri via the builder, so hand-craft
            # the ked to produce a spec-conformant v1 exn on the wire.
            # Must route to kramMSGC (non-transactional), not kramTMSC.

            fakePrior = "E" + "A" * 43
            v1ExnWithPKed = {
                'v': versify(proto=Protocols.keri,
                                    pvrsn=Vrsn_1_0,
                                    kind=Kinds.json),
                't': Ilks.exn,
                'd': '',
                'i': senderHab.pre,
                'p': fakePrior,    # non-empty prior, no x field
                'dt': stamp,
                'r': '/test/exchange',
                'q': {},
                'a': dict(n='v1p'),
            }
            _, v1ExnWithPKed = Saider.saidify(sad=v1ExnWithPKed)
            v1ExnWithP = SerderKERI(sad=v1ExnWithPKed, verify=False)

            # Confirm no x field present in the v1 ked
            assert v1ExnWithP.ked.get('x', None) is None
            # Confirm p field is non-empty
            assert v1ExnWithP.ked.get('p', '') != ''

            sigers = senderHab.mgr.sign(ser=v1ExnWithP.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            result = kramer.kramit(v1ExnWithP, **kwa)

            assert result is not None  # accepted
            # Routed to non-transactional cache
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, v1ExnWithP.said))
            assert cache is not None
            # NOT written to transactional cache
            assert receiverHby.db.kramTMSC.get(
                keys=(senderHab.pre, fakePrior, v1ExnWithP.said)) is None


            # Step 3: v1 exn that carries an x field (malformed/cross-version)
            # The v1 serializer rejects x as an unallowed field, so we
            # hand-craft the ked to simulate a malformed message arriving
            # on the wire. The x field must be ignored by kramit; the
            # message must still route to kramMSGC, not kramTMSC.

            fakeXid = "E" + "B" * 43
            v1ExnKed = {
                'v': versify(proto=Protocols.keri,
                                    pvrsn=Vrsn_1_0,
                                    kind=Kinds.json),
                't': Ilks.exn,
                'd': '',           # placeholder, will be replaced by SAID derivation
                'i': senderHab.pre,
                'p': "E" + "A" * 43,
                'x': fakeXid,      # injected — invalid in v1 schema
                'dt': stamp,
                'r': '/test/exchange',
                'q': {},
                'a': dict(n='v1x'),
            }
            # Derive SAID and raw bytes directly, bypassing builder validation
            _, v1ExnKed = Saider.saidify(sad=v1ExnKed)
            v1ExnWithX = SerderKERI(sad=v1ExnKed, verify=False)

            sigers = senderHab.mgr.sign(ser=v1ExnWithX.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            result = kramer.kramit(v1ExnWithX, **kwa)

            assert result is not None  # accepted
            # Still routes to non-transactional cache (x field ignored for v1)
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, v1ExnWithX.said))
            assert cache is not None
            # NOT written to transactional cache under the injected x field
            assert receiverHby.db.kramTMSC.get(
                keys=(senderHab.pre, fakeXid, v1ExnWithX.said)) is None


            # Step 4: v2 exn with x field -> transactional (kramTMSC) cache
            # Confirms the version gate does not regress the v2 path.

            # First seed a v2 xip so kramTMSC has an entry for the exchange ID
            v2Xip = exchept(sender=senderHab.pre,
                            receiver=receiverHab.pre,
                            route="/test/exchange",
                            stamp=stamp)

            xipSigers = senderHab.mgr.sign(ser=v2Xip.raw,
                                            verfers=senderHab.kever.verfers,
                                            indexed=True)
            xipResult = kramer.kramit(v2Xip, **dict(ssgs=[(skPrefixer, xipSigers)]))
            assert xipResult is not None  # xip accepted

            v2Exn = exchange(sender=senderHab.pre,
                             receiver=receiverHab.pre,
                             xid=v2Xip.said,
                             route="/test/exchange",
                             attributes=dict(n='v2x'),
                             stamp=stamp)

            # Confirm x field present in v2 ked
            assert v2Exn.ked.get('x', None) is not None

            sigers = senderHab.mgr.sign(ser=v2Exn.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            result = kramer.kramit(v2Exn, **kwa)

            assert result is not None  # accepted
            # Routed to transactional cache
            cache = receiverHby.db.kramTMSC.get(
                keys=(senderHab.pre, v2Xip.said, v2Exn.said))
            assert cache is not None
            # NOT written to non-transactional cache
            assert receiverHby.db.kramMSGC.get(
                keys=(senderHab.pre, v2Exn.said)) is None

    """Done Test"""


def test_non_auth_attachments_stored(mockHelpingNowUTC):
    """Test that all non-authenticator attachments are stored in their
    respective partial databases during multi-key accumulation and are
    retrievable after threshold satisfaction.

    Covers: trqs, tsgs, sscs, ssts, frcs, tdcs, ptds, bsqs, bsss, tmqs
    populated on partial delivery, idempotency on re-delivery, persistence
    after threshold met.
    """

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="naaSender", base="test", salt=salt1) as senderHby,
          openHby(name="naaReceiver", base="test", salt=salt2) as receiverHby):

        # Multi-key sender
        senderHab = senderHby.makeHab(name="naaSender", isith='2', icount=3,
                                      transferable=True)
        assert len(senderHab.kever.verfers) == 3

        receiverHby.makeHab(name="naaReceiver", isith='1', icount=1,
                            transferable=True)

        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        with openCF(name="naaKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)

            msg = query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            allSigers = senderHab.mgr.sign(ser=msg.raw,
                                           verfers=senderHab.kever.verfers,
                                           indexed=True)

            partialKey = (senderHab.pre, msg.said)

            # Build non-auth attachments to include in kwa

            senderKever = receiverHby.db.kevers[senderHab.pre]
            seqner = Seqner(sn=senderKever.sner.num)
            saider = Saider(qb64=senderKever.serder.said)
            diger = Diger(ser=msg.raw)

            # trqs: trans receipt quadruple (prefixer, seqner, saider, siger)
            trqs = [(prefixer, seqner, saider, allSigers[0])]

            # tsgs: trans last sig group (prefixer, seqner, saider, [sigers])
            tsgs = [(prefixer, seqner, saider, [allSigers[0]])]

            # sscs: first seen seal couple (seqner, saider) issuing or delegating
            sscs = [(seqner, saider)]

            # ssts: source seal triple (prefixer, seqner, saider) issued or delegated
            ssts = [(prefixer, seqner, saider)]

            # frcs: first seen replay couple (seqner, dater)
            firner = Seqner(sn=0)
            dater = Dater(dts=stamp)
            frcs = [(firner, dater)]

            # tdcs: typed digest seal couple (verser, diger)
            verser = Verser(pvrsn=Vrsn_2_0)
            tdcs = [(verser, diger)]

            # ptds: pathed stream (raw bytes)
            ptds = [b'\x00\x01\x02\x03']

            # bsqs: blind state quadruple (diger, noncer, noncer, labeler)
            noncer0 = Noncer()
            noncer1 = Noncer()
            labeler = Labeler(label='test')
            bsqs = [(diger, noncer0, noncer1, labeler)]

            # bsss: bound state sextuple (diger, noncer, noncer, labeler, number, noncer)
            number = Number(num=1)
            noncer2 = Noncer()
            bsss = [(diger, noncer0, noncer1, labeler, number, noncer2)]

            # tmqs: type media quadruple (diger, noncer, labeler, texter)
            texter = Texter(text='application/json')
            tmqs = [(diger, noncer0, labeler, texter)]


            # First delivery with 1 sig (below threshold) + non-auth attachments

            kwa = dict(ssgs=[(prefixer, [allSigers[0]])],
                       trqs=trqs, tsgs=tsgs, sscs=sscs, ssts=ssts,
                       frcs=frcs, tdcs=tdcs, ptds=ptds,
                       bsqs=bsqs, bsss=bsss, tmqs=tmqs)
            kvy.processMsg(msg, **kwa)

            # Threshold not met, partials populated
            assert receiverHby.db.kramPMKM.get(keys=partialKey) is not None
            kramPMKS = receiverHby.db.kramPMKS.get(keys=partialKey)
            assert len(kramPMKS) == 1

            # All non-auth attachment dbs populated
            assert len(receiverHby.db.kramTRQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTSGS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSTS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramFRCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTDCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramPTDS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSSS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTMQS.get(keys=partialKey)) == 1

            assert len(kvy.cues) == 0


            # Re-delivery of same non-auth attachments is idempotent

            kvy.processMsg(msg, **kwa)

            assert len(receiverHby.db.kramTRQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTSGS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSTS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramFRCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTDCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramPTDS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSSS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTMQS.get(keys=partialKey)) == 1


            # Second delivery with 2nd sig meets threshold
            # Non-auth attachments should persist (pruner responsibility)

            kwa2 = dict(ssgs=[(prefixer, [allSigers[2]])],
                        trqs=trqs, tsgs=tsgs, sscs=sscs, ssts=ssts,
                        frcs=frcs, tdcs=tdcs, ptds=ptds,
                        bsqs=bsqs, bsss=bsss, tmqs=tmqs)
            kvy.processMsg(msg, **kwa2)

            # Threshold met, cue generated
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"

            # Non-auth attachments persist (pruner cleans up, not kramit)
            assert len(receiverHby.db.kramTRQS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramTSGS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramSSCS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramSSTS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramFRCS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramTDCS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramPTDS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramBSQS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramBSSS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramTMQS.get(keys=partialKey)) >= 1

    """Done Test"""


def test_non_auth_attachments_empty_kwa(mockHelpingNowUTC):
    """Test that _storeNonAuthAttachments is a no-op when kwa contains no
    non-auth attachment keys. Partial dbs remain empty.
    """

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="naesSender", base="test", salt=salt1) as senderHby,
          openHby(name="naesReceiver", base="test", salt=salt2) as receiverHby):

        senderHab = senderHby.makeHab(name="naesSender", isith='2', icount=3,
                                      transferable=True)
        receiverHby.makeHab(name="naesReceiver", isith='1', icount=1,
                            transferable=True)

        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)

        with openCF(name="naesKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)

            msg = query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            allSigers = senderHab.mgr.sign(ser=msg.raw,
                                           verfers=senderHab.kever.verfers,
                                           indexed=True)

            partialKey = (senderHab.pre, msg.said)


            # Partial delivery with no non-auth attachments in kwa

            kwa = dict(ssgs=[(prefixer, [allSigers[0]])])
            kvy.processMsg(msg, **kwa)

            # Sig partial populated
            assert receiverHby.db.kramPMKM.get(keys=partialKey) is not None

            # All non-auth attachment dbs empty
            assert receiverHby.db.kramTRQS.get(keys=partialKey) == []
            assert receiverHby.db.kramTSGS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSCS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSTS.get(keys=partialKey) == []
            assert receiverHby.db.kramFRCS.get(keys=partialKey) == []
            assert receiverHby.db.kramTDCS.get(keys=partialKey) == []
            assert receiverHby.db.kramPTDS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSQS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSSS.get(keys=partialKey) == []
            assert receiverHby.db.kramTMQS.get(keys=partialKey) == []

    """Done Test"""


def test_rem_non_auth_attachments(mockHelpingNowUTC):
    """Test _remNonAuthAttachments clears all ten non-auth dbs for a key."""

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="remSender", base="test", salt=salt1) as senderHby,
          openHby(name="remReceiver", base="test", salt=salt2) as receiverHby):

        senderHab = senderHby.makeHab(name="remSender", isith='2', icount=3,
                                      transferable=True)
        receiverHby.makeHab(name="remReceiver", isith='1', icount=1,
                            transferable=True)

        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)

        with openCF(name="remKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)

            msg = query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            allSigers = senderHab.mgr.sign(ser=msg.raw,
                                           verfers=senderHab.kever.verfers,
                                           indexed=True)

            partialKey = (senderHab.pre, msg.said)

            senderKever = receiverHby.db.kevers[senderHab.pre]
            seqner = Seqner(sn=senderKever.sner.num)
            saider = Saider(qb64=senderKever.serder.said)
            diger = Diger(ser=msg.raw)

            # Populate all ten non-auth dbs directly
            receiverHby.db.kramTRQS.add(keys=partialKey,
                                    val=(prefixer, seqner, saider, allSigers[0]))
            receiverHby.db.kramTSGS.add(keys=partialKey,
                                    val=(prefixer, seqner, saider, allSigers[0]))
            receiverHby.db.kramSSCS.add(keys=partialKey, val=(seqner, saider))
            receiverHby.db.kramSSTS.add(keys=partialKey, val=(prefixer, seqner, saider))

            firner = Seqner(sn=0)
            dater = Dater(dts=stamp)
            receiverHby.db.kramFRCS.add(keys=partialKey, val=(firner, dater))

            verser = Verser(pvrsn=Vrsn_2_0)
            receiverHby.db.kramTDCS.add(keys=partialKey, val=(verser, diger))

            receiverHby.db.kramPTDS.add(keys=partialKey, val=b'\x00\x01')

            noncer0 = Noncer()
            noncer1 = Noncer()
            labeler = Labeler(label='test')
            receiverHby.db.kramBSQS.add(keys=partialKey,
                                    val=(diger, noncer0, noncer1, labeler))

            number = Number(num=1)
            noncer2 = Noncer()
            receiverHby.db.kramBSSS.add(keys=partialKey,
                                    val=(diger, noncer0, noncer1, labeler, number, noncer2))

            texter = Texter(text='application/json')
            receiverHby.db.kramTMQS.add(keys=partialKey,
                                    val=(diger, noncer0, labeler, texter))

            # Confirm all populated
            assert len(receiverHby.db.kramTRQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTSGS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSTS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramFRCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTDCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramPTDS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSSS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTMQS.get(keys=partialKey)) == 1

            # Call _remNonAuthAttachments
            kramer._remNonAuthAttachments(partialKey)

            # All ten cleared
            assert receiverHby.db.kramTRQS.get(keys=partialKey) == []
            assert receiverHby.db.kramTSGS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSCS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSTS.get(keys=partialKey) == []
            assert receiverHby.db.kramFRCS.get(keys=partialKey) == []
            assert receiverHby.db.kramTDCS.get(keys=partialKey) == []
            assert receiverHby.db.kramPTDS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSQS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSSS.get(keys=partialKey) == []
            assert receiverHby.db.kramTMQS.get(keys=partialKey) == []

    """Done Test"""


def test_stale_tsgs(mockHelpingNowUTC):
    """Test that non-current but verifiable tsgs are collected, stored, and
    forwarded in-band via kwa['tsgs'].

    A tsg whose (number, sdiger) references a past establishment event in the
    sender's KEL verifies against the verfers from that historical event, not
    the current kever. Such stale tsgs are not counted toward the current
    threshold but are folded into kwa['tsgs'] so downstream processors see
    the full set of signers across key states.

    Covers:
        - stale tsg verified against historical key state appears in
          sigResult.stale_tsgs
        - stale tsg with no matching historical event produces empty
          stale_tsgs (ignored)
        - fast path (threshold met on first delivery): stale tsgs merged
          into kwa['tsgs'] directly from sigResult before return
        - accumulation path (threshold met on later delivery): stale tsgs
          stored in db.tsgs alongside current-keystate tsgs, present at
          threshold satisfaction
    """

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="staleSender", base="test", salt=salt1) as senderHby,
          openHby(name="staleReceiver", base="test", salt=salt2) as receiverHby):

        # 2-of-3 multi-key sender
        senderHab = senderHby.makeHab(name="staleSender", isith='2', icount=3,
                                      transferable=True)
        assert len(senderHab.kever.verfers) == 3

        receiverHby.makeHab(name="staleReceiver", isith='1', icount=1,
                            transferable=True)

        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)

        # Cross-feed sender ICP (sn=0) to receiver
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        # Capture pre-rotation state: sn=0 said and verfers
        icpSaid = senderHab.kever.serder.said
        icpVerfers = list(senderHab.kever.verfers)
        icpSn = senderHab.kever.sn
        assert icpSn == 0

        # Rotate sender so sn=1 is now current
        rotMsg = senderHab.rotate()
        Parser(version=Vrsn_1_0).parse(ims=bytearray(rotMsg), kvy=crossKvy)
        assert senderHab.kever.sn == 1

        # Confirm receiver sees sn=1 as current
        receiverKever = receiverHby.db.kevers[senderHab.pre]
        assert receiverKever.sner.num == 1

        with openCF(name="staleKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)

            # Step 1: stale tsg verified against historical event
            #
            # Sign msg with sn=0 (pre-rotation) keys. Present as a tsg
            # referencing (sn=0, icpSaid). Current kever is sn=1 so this
            # tsg fails the current keystate gate but should verify
            # historically and appear in sigResult.stale_tsgs.

            msg = query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre,
                                            n='stale01'),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)

            # Sign with old (sn=0) keys
            oldSigers = senderHab.mgr.sign(ser=msg.raw,
                                           verfers=icpVerfers,
                                           indexed=True)

            # Also sign with current (sn=1) keys so threshold can be met
            currentSigers = senderHab.mgr.sign(ser=msg.raw,
                                               verfers=senderHab.kever.verfers,
                                               indexed=True)

            oldSeqner = Seqner(sn=icpSn)
            oldSaider = Saider(qb64=icpSaid)
            curSeqner = Seqner(sn=receiverKever.sner.num)
            curSaider = Saider(qb64=receiverKever.serder.said)

            # Provide 2 current-keystate sigs (meets 2-of-3 threshold) plus
            # one stale tsg from sn=0 keys. ssgs is required by the downstream
            # qry handler to extract source; tsgs alone satisfy KRAM but not
            # the dispatcher.
            staleTsg = (prefixer, oldSeqner, oldSaider, [oldSigers[0]])
            currentTsgs = [(prefixer, curSeqner, curSaider, [currentSigers[0],
                                                              currentSigers[1]])]

            kwa = dict(ssgs=[(prefixer, currentSigers)],
                       tsgs=currentTsgs + [staleTsg])
            kvy.processMsg(msg, **kwa)

            # Fast path: threshold met on first delivery.
            # Cache created, no partials stored.
            partialKey = (senderHab.pre, msg.said)
            cache = receiverHby.db.kramMSGC.get(keys=partialKey)
            assert cache is not None
            assert receiverHby.db.kramPMKM.get(keys=partialKey) is None

            # stale tsg stored in db.tsgs alongside current-keystate tsgs
            # (merged into kwa['tsgs'] before _storeNonAuthAttachments — but
            # on the fast path _storeNonAuthAttachments is never called, so
            # the stale tsg does NOT land in db.tsgs here. Instead it was
            # merged into kwa['tsgs'] in-memory for downstream forwarding.)
            # Verify downstream dispatch occurred (cue generated).
            assert len(kvy.cues) > 0
            kvy.cues.clear()


            # Step 2: stale tsg with no matching historical event is ignored

            msg2 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre,
                                             n='stale02'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            currentSigers2 = senderHab.mgr.sign(ser=msg2.raw,
                                                verfers=senderHab.kever.verfers,
                                                indexed=True)

            # Reference sn=999 does not exist in receiver's KEL copy
            bogusSeqner = Seqner(sn=999)
            bogusSaider = Saider(qb64=icpSaid)
            bogusStaleTsg = (prefixer, bogusSeqner, bogusSaider, [oldSigers[0]])

            currentTsgs2 = [(prefixer, curSeqner, curSaider, [currentSigers2[0],
                                                               currentSigers2[1]])]

            kwa2 = dict(ssgs=[(prefixer, currentSigers2)],
                        tsgs=currentTsgs2 + [bogusStaleTsg])
            kvy.processMsg(msg2, **kwa2)

            # Accepted via current-keystate sigs; bogus stale tsg silently ignored
            cache2 = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg2.said))
            assert cache2 is not None
            kvy.cues.clear()


            # Step 3: accumulation path — stale tsg stored in db.tsgs
            #
            # First delivery: 1 current-keystate sig (below 2-of-3 threshold)
            # plus one stale tsg. Stale tsg should be folded into kwa['tsgs']
            # and stored in db.tsgs under the partial key.
            # Second delivery: completes the threshold. db.tsgs should contain
            # both current-keystate and stale entries.

            msg3 = query(pre=senderHab.pre,
                                  route="ksn",
                                  query=dict(i=senderHab.pre, src=senderHab.pre,
                                             n='stale03'),
                                  stamp=stamp,
                                  pvrsn=Vrsn_2_0)

            currentSigers3 = senderHab.mgr.sign(ser=msg3.raw,
                                                verfers=senderHab.kever.verfers,
                                                indexed=True)
            oldSigers3 = senderHab.mgr.sign(ser=msg3.raw,
                                            verfers=icpVerfers,
                                            indexed=True)

            partialKey3 = (senderHab.pre, msg3.said)
            staleTsg3 = (prefixer, oldSeqner, oldSaider, [oldSigers3[0]])

            # First delivery: 1 current sig + stale tsg, threshold not met
            kwa3a = dict(ssgs=[(prefixer, [currentSigers3[0]])],
                         tsgs=[(prefixer, curSeqner, curSaider,
                                [currentSigers3[0]])] + [staleTsg3])
            kvy.processMsg(msg3, **kwa3a)

            assert receiverHby.db.kramPMKM.get(keys=partialKey3) is not None
            pmks3 = receiverHby.db.kramPMKS.get(keys=partialKey3)
            assert len(pmks3) == 1  # only 1 current-keystate sig so far

            # db.tsgs should contain both the current-keystate tsg entry AND
            # the stale tsg entry (folded in via kwa['tsgs'] before store)
            tsgs3 = receiverHby.db.kramTSGS.get(keys=partialKey3)
            assert len(tsgs3) == 2  # 1 current + 1 stale

            assert len(kvy.cues) == 0

            # Second delivery: 1 more current sig, completes 2-of-3 threshold
            kwa3b = dict(ssgs=[(prefixer, [currentSigers3[1]])],
                         tsgs=[(prefixer, curSeqner, curSaider,
                                [currentSigers3[1]])])
            kvy.processMsg(msg3, **kwa3b)

            # Threshold met, cue generated
            assert len(kvy.cues) > 0
            kvy.cues.clear()

            # db.tsgs still holds all entries including the stale one
            tsgs3_after = receiverHby.db.kramTSGS.get(keys=partialKey3)
            assert len(tsgs3_after) >= 2  # stale entry persists until pruner

    """Done Test"""


def test_cue_ks_non_transactioned(mockHelpingNowUTC):
    """
    Test cue key state retrieval for non transactional messages

    Covers: new cache for single-key, multi-key and reference seal
    """
    # Step 1: Setup

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64
    salt3 = Salter(raw=b'0123456789abcdeh').qb64
    salt4 = Salter(raw=b'0123456789abcdei').qb64

    with (openHby(name="senderSk", base="test", salt=salt1) as senderSkHby,
          openHby(name="senderMk", base="test", salt=salt2) as senderMkHby,
          openHby(name="knownSender", base="test", salt=salt3) as knownSenderHby,
          openHby(name="receiver", base="test", salt=salt4) as receiverHby):

        # Create transferable single-key sender (no witnesses)
        senderSkHab = senderSkHby.makeHab(name="senderSk", isith='1', icount=1,
                                      transferable=True)
        # Create multi-key sender
        senderMkHab = senderMkHby.makeHab(name="senderMk", isith='2', icount=3,
                                          transferable=True)
        # Create known Sender
        kownSenderHab = knownSenderHby.makeHab(name="knownSender", isith='1', icount=1,
                                            transferable=True)

        # Create receiver hab (needed for receiver db context)
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1,
                                          transferable=True)

        # Do not cross-feed senders ICP to receiver so they remain unknown to sender
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)

        senderSkHab.makeOwnEvent(sn=0)
        senderMkHab.makeOwnEvent(sn=0)
        assert senderSkHab.pre not in crossKvy.kevers
        assert senderMkHab.pre not in crossKvy.kevers

        # Cross for the known sender
        senderIcp = kownSenderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert kownSenderHab.pre in crossKvy.kevers

        # Create Kramer + Kevery
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            # Stamp for events
            stamp = helping.nowIso8601()

            # Single-key Missing KEL

            skPrefixer = Prefixer(qb64=senderSkHab.pre)

            msg = query(pre=senderSkHab.pre,
                                            route="ksn",
                                            query=dict(i=senderSkHab.pre, src=senderSkHab.pre),
                                            stamp=stamp,
                                            pvrsn=Vrsn_2_0)

            sigers = senderSkHab.mgr.sign(ser=msg.raw,
                                                verfers=senderSkHab.kever.verfers,
                                                indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            with pytest.raises(MissingSenderKeyStateError):
                kvy.processMsg(msg, **kwa)

            # Assert cue key state retrieval notification
            cue = kvy.cues.popleft()
            assert cue['kin'] == 'keystate'
            assert cue['aid'] == senderSkHab.pre
            assert cue['sn'] is None
            kvy.cues.clear()


            # Multi-key missing KEL

            mkPrefixer = Prefixer(qb64=senderMkHab.pre)

            msg = query(pre=senderMkHab.pre,
                                            route="ksn",
                                            query=dict(i=senderMkHab.pre, src=senderMkHab.pre),
                                            stamp=stamp,
                                            pvrsn=Vrsn_2_0)

            sigers = senderMkHab.mgr.sign(ser=msg.raw,
                                                verfers=senderMkHab.kever.verfers,
                                                indexed=True)
            kwa = dict(ssgs=[(mkPrefixer, sigers)])

            with pytest.raises(MissingSenderKeyStateError):
                kvy.processMsg(msg, **kwa)

            # Assert cue key state retrieval notification
            cue = kvy.cues.popleft()
            assert cue['kin'] == 'keystate'
            assert cue['aid'] == senderMkHab.pre
            assert cue['sn'] is None
            kvy.cues.clear()


            # Seal reference missing KEL event

            ixnSaid = kownSenderHab.kever.serder.said

            msg = query(pre=kownSenderHab.pre,
                                    route="ksn",
                                    query=dict(i=kownSenderHab.pre, src=kownSenderHab.pre, n='3f'),
                                    stamp=stamp,
                                    pvrsn=Vrsn_2_0)

            # Reference sn=999 (event doesn't exist in receiver's copy)
            sscs = [(Seqner(sn=999), Saider(qb64=ixnSaid))]
            kwa = dict(sscs=sscs)  # pure sscs, no sigs

            kvy.processMsg(msg, **kwa)

            cache = receiverHby.db.kramMSGC.get(keys=(kownSenderHab.pre, msg.said))
            assert cache is None  # no cache

            # Assert for cue key state retrieval
            cue = kvy.cues.popleft()
            assert cue['kin'] == "keystate"
            assert cue['aid'] == kownSenderHab.pre
            assert cue['sn'] == 0
            kvy.cues.clear()


def test_cue_ks_transactioned(mockHelpingNowUTC):
    """
    Test cue key state retrieval for transactional exchange messages

    Covers: new cache for single-key, multi-key and reference seal
    """
    # Step 1: Setup

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64
    salt3 = Salter(raw=b'0123456789abcdeh').qb64
    salt4 = Salter(raw=b'0123456789abcdei').qb64

    with (openHby(name="senderSk", base="test", salt=salt1) as senderSkHby,
          openHby(name="senderMk", base="test", salt=salt2) as senderMkHby,
          openHby(name="knownSender", base="test", salt=salt3) as knownSenderHby,
          openHby(name="receiver", base="test", salt=salt4) as receiverHby):

        # Create transferable single-key sender (no witnesses)
        senderSkHab = senderSkHby.makeHab(name="senderSk", isith='1', icount=1,
                                      transferable=True)
        # Create multi-key sender
        senderMkHab = senderMkHby.makeHab(name="senderMk", isith='2', icount=3,
                                          transferable=True)
        # Create known Sender
        kownSenderHab = knownSenderHby.makeHab(name="knownSender", isith='1', icount=1,
                                            transferable=True)

        # Create receiver hab (needed for receiver db context)
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1,
                                          transferable=True)

        # Do not cross-feed senders ICP to receiver so they remain unknown to sender
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)

        senderSkHab.makeOwnEvent(sn=0)
        senderMkHab.makeOwnEvent(sn=0)
        assert senderSkHab.pre not in crossKvy.kevers
        assert senderMkHab.pre not in crossKvy.kevers

        # Cross for the known sender
        senderIcp = kownSenderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert kownSenderHab.pre in crossKvy.kevers

        # Create Kramer + Kevery
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            stamp = helping.nowIso8601()

            # Get the prefix for the single-key sender
            skPrefixer = Prefixer(qb64=senderSkHab.pre)

            # Create the exchange start event
            xip = exchept(sender=senderSkHab.pre,
                          receiver=receiverHab.pre,
                          route="/test/exchange",
                          stamp=stamp)

            # Sign xip
            sigers = senderSkHab.mgr.sign(ser=xip.raw,
                                    verfers=senderSkHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(skPrefixer, sigers)])

            # Call kramit directly (processMsg rejects xip)
            with pytest.raises(MissingSenderKeyStateError):
                result = kramer.kramit(xip, **kwa)

            # Assert cue key state retrieval notification
            cue = kvy.cues.popleft()
            assert cue['kin'] == 'keystate'
            assert cue['aid'] == senderSkHab.pre
            assert cue['sn'] is None
            kvy.cues.clear()


            # Multi-key missing KEL

            mkPrefixer = Prefixer(qb64=senderMkHab.pre)

            xip = exchept(sender=senderMkHab.pre,
                          receiver=receiverHab.pre,
                          route="/test/exchange",
                          stamp=stamp)

            # Sign xip
            sigers = senderMkHab.mgr.sign(ser=xip.raw,
                                    verfers=senderMkHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(mkPrefixer, sigers)])

            # Call kramit directly (processMsg rejects xip)
            with pytest.raises(MissingSenderKeyStateError):
                result = kramer.kramit(xip, **kwa)

            # Assert cue key state retrieval notification
            cue = kvy.cues.popleft()
            assert cue['kin'] == 'keystate'
            assert cue['aid'] == senderMkHab.pre
            assert cue['sn'] is None
            kvy.cues.clear()


            # Seal reference missing KEL event

            xip = exchept(sender=kownSenderHab.pre,
                          receiver=receiverHab.pre,
                          route="/test/exchange",
                          stamp=stamp)

            # Build sscs referencing the ixn event
            ixnSaid = kownSenderHab.kever.serder.said

            # Reference sn=999 (event doesn't exist in receiver's copy)
            sscs = [(Seqner(sn=999), Saider(qb64=ixnSaid))]
            kwa = dict(sscs=sscs)  # pure sscs, no sigs

            # Call kramit directly (processMsg rejects xip)
            kramer.kramit(xip, **kwa)

            # Assert for cue key state retrieval
            cue = kvy.cues.popleft()
            assert cue['kin'] == "keystate"
            assert cue['aid'] == kownSenderHab.pre
            assert cue['sn'] == 0
            kvy.cues.clear()


def test_aid_allow_deny(mockHelpingNowUTC):
    """
    Test AID based allow/deny in processMsg()
    """
    # Step 1: Setup
    
    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64
    salt3 = Salter(raw=b'0123456789abcdeh').qb64

    with (openHby(name="sender", base="test", salt=salt1) as allowSenderHby,
          openHby(name="senderNT", base="test", salt=salt2) as denySenderHby,
          openHby(name="receiver", base="test", salt=salt3) as receiverHby):

        # Create single-key sender
        allowHab = allowSenderHby.makeHab(name="sender", isith='1', icount=1,
                                      transferable=True)
        # Create single-key sender
        denyHab = denySenderHby.makeHab(name="senderNT", isith='1', icount=1,
                                          transferable=True)
        # Create receiver hab (needed for receiver db context)
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1,
                                          transferable=True)

        # Parse sender ICPs into receiver's db via a cross-feed Kevery.
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)

        allowSenderIcp = allowHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(allowSenderIcp), kvy=crossKvy)
        assert allowHab.pre in crossKvy.kevers

        denySenderIcp = denyHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(denySenderIcp), kvy=crossKvy)
        assert denyHab.pre in crossKvy.kevers

        # Create Kramer with config
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            assert kramer.enabled
            # Create Kevery with kramer for KRAM testing
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)
 
            # Put AID in Deny list of Kevery
            kvy.denyList.add(denyHab.pre)

            # Build qry message with mocked timestamp
            stamp = helping.nowIso8601()
            msg = query(pre=denyHab.pre,
                        route="ksn",
                        query=dict(i=denyHab.pre, src=denyHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = denyHab.mgr.sign(ser=msg.raw,
                                        verfers=denyHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=denyHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])
            kvy.processMsg(msg, **kwa)

            # Assert cache was not created
            assert receiverHby.db.kramMSGC.get(keys=(denyHab.pre, msg.said)) is None

            # Remove denyHab from deny list
            kvy.denyList.discard(denyHab.pre)

            # Add allowHab to allow list           
            kvy.allowList.add(allowHab.pre)

            msg = query(pre=allowHab.pre,
                        route="ksn",
                        query=dict(i=allowHab.pre, src=allowHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = allowHab.mgr.sign(ser=msg.raw,
                                        verfers=allowHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=allowHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])
            kvy.processMsg(msg, **kwa)

            # Assert cache was created
            assert receiverHby.db.kramMSGC.get(keys=(allowHab.pre, msg.said)) is not None

            # Send another message with denyHab 
            msg = query(pre=denyHab.pre,
                        route="ksn",
                        query=dict(i=denyHab.pre, src=denyHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = denyHab.mgr.sign(ser=msg.raw,
                                        verfers=denyHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=denyHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])
            kvy.processMsg(msg, **kwa)

            # Assert cache was not created because the allow list is active and denyHab is not 
            # in the allow list
            assert receiverHby.db.kramMSGC.get(keys=(denyHab.pre, msg.said)) is None

            # Add denyHab to the allow list
            kvy.allowList.add(denyHab.pre)

            # Re process the message
            kvy.processMsg(msg, **kwa)

            # Assert cache was created
            assert receiverHby.db.kramMSGC.get(keys=(denyHab.pre, msg.said)) is not None



def test_dynamic_cache_increase(fakeHelpingClock):
    """
    Tests that Kramer.changeConfig() correctly applies:
    - immediate prune increases
    - staged accept increases
    - preserves drift (d)
    using only old CF vs new CF
    """

    clock = fakeHelpingClock
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="sender", base="test", salt=salt_sender, temp=True) as senderHby,
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):

        # 1. Initial CF (old config)
        old_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [1000, 1000, 1000, 1000, 1000, 1000, 1000],  # d,sl,ll,xl,psl,pll,pxl
                }
            }
        }

        with openCF(name="kram", base="test", temp=True) as cf:
            cf.put(old_cfg)


            # 2. Instantiate Kramer with old config

            kramer = Kramer(db=receiverHby.db, cf=cf)

            rec = receiverHby.db.kramCTYP.get("~")
            assert rec.d == 1000
            assert rec.sl == 1000
            assert rec.psl == 1000


            # 3. New CF (increase accept + prune, same drift)

            new_cfg = {
                "kram": {
                    "enabled": True,
                    "caches": {
                        "~": [1000, 5000, 5000, 5000, 5000, 5000, 5000],
                    }
                }
            }
            cf.put(new_cfg)

            # 4. Apply dynamic update

            kramer.changeConfig(cf)

            rec = receiverHby.db.kramCTYP.get("~")

            # Drift must remain unchanged
            assert rec.d == 1000

            # Accept windows remain OLD
            assert rec.sl == 1000
            assert rec.ll == 1000
            assert rec.xl == 1000

            # Prune windows update immediately
            assert rec.psl == 5000
            assert rec.pll == 5000
            assert rec.pxl == 5000

            # Pending state exists
            assert "~" in kramer._pending
            pend = kramer._pending["~"]
            assert pend["sl_new"] == 5000
            assert pend["delta"] == 4000


            # 5. Advance time LESS than delta → no change
            assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

            clock.advance(seconds=3)
            assert helping.nowIso8601() == "2021-01-01T00:00:03.000000+00:00"

            # kramer.reconcileConfig()

            rec = receiverHby.db.kramCTYP.get("~")
            assert rec.sl == 1000
            assert rec.d == 1000
            assert "~" in kramer._pending


            # 6. Advance time BEYOND delta → accept updates

            clock.advance(seconds=1)

            # Reconciliation is called manually since there is no msg to process
            kramer.reconcileConfig()

            rec = receiverHby.db.kramCTYP.get("~")

            # Accept windows updated
            assert rec.sl == 5000
            assert rec.ll == 5000
            assert rec.xl == 5000

            # Drift still preserved
            assert rec.d == 1000

            # Prune windows remain correct
            assert rec.psl == 5000
            assert rec.pll == 5000
            assert rec.pxl == 5000

            # Pending cleaned up
            assert "~" not in kramer._pending


def test_dynamic_cache_decrease(fakeHelpingClock):
    """
    Tests that Kramer.changeConfig() correctly applies:
    - immediate accept decreases
    - immediate prune decreases
    - preserves drift (d)
    - no staging occurs
    """

    clock = fakeHelpingClock
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="sender", base="test", salt=salt_sender, temp=True) as senderHby,
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):

        # 1. Initial CF (old config)
        old_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [1000, 5000, 5000, 5000, 5000, 5000, 5000],
                }
            }
        }

        with openCF(name="kram", base="test", temp=True) as cf:
            cf.put(old_cfg)

            
            # Instantiate Kramer with old config
            
            kramer = Kramer(db=receiverHby.db, cf=cf)

            rec = receiverHby.db.kramCTYP.get("~")
            assert rec.d == 1000
            assert rec.sl == 5000
            assert rec.psl == 5000

            
            # New CF (pure decrease)
            new_cfg = {
                "kram": {
                    "enabled": True,
                    "caches": {
                        "~": [1000, 1000, 1000, 1000, 1000, 1000, 1000],
                    }
                }
            }
            cf.put(new_cfg)

            # 4. Apply dynamic update
            kramer.changeConfig(cf)

            rec = receiverHby.db.kramCTYP.get("~")

            # Drift preserved
            assert rec.d == 1000

            # Accept windows decreased immediately
            assert rec.sl == 1000
            assert rec.ll == 1000
            assert rec.xl == 1000

            # Prune windows decreased immediately
            assert rec.psl == 1000
            assert rec.pll == 1000
            assert rec.pxl == 1000

            # No pending state should exist
            assert "~" not in kramer._pending

            # Advance time — nothing should change
            clock.advance(10000)
            # kramer.reconcileConfig()

            rec = receiverHby.db.kramCTYP.get("~")

            # Still the decreased values
            assert rec.sl == 1000
            assert rec.psl == 1000
            assert "~" not in kramer._pending


def test_existing_caches_unchanged_on_config_update(fakeHelpingClock):
    """
    Ensures that existing caches in message-ID cache DB (msgc)
    remain unchanged when Kramer cache-type configuration changes.
    """

    clock = fakeHelpingClock
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="sender", base="test", salt=salt_sender, temp=True) as senderHby,
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):

        # Initial CF (old config)
        old_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [1000, 1000, 1000, 1000, 1000, 1000, 1000],
                }
            }
        }

        # Create transferable single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1,
                                      transferable=True)

        # Create receiver hab (needed for receiver db context)
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1,
                                          transferable=True)

        # Parse sender ICPs into receiver's db via a cross-feed Kevery.
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        with openCF(name="kram", base="test", temp=True) as cf:
            # Set the initial config
            cf.put(old_cfg)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            # Stamp for events            
            stamp = helping.nowIso8601()
            
            # Create an existing cache entry

                        # Happy path, attachments pruned after threshold is met
            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)

            msg = query(pre=senderHab.pre,
                        route="ksn",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.d == 1000   # drift from config
            assert cache.ml == 1000  # short lag (assk)
            assert cache.pml == 1000  # prune short lag (assk)
            
            # New CF (increase accept + prune)
            new_cfg = {
                "kram": {
                    "enabled": True,
                    "caches": {
                        "~": [1000, 5000, 5000, 5000, 5000, 5000, 5000],
                    }
                }
            }
            # Set the new config
            cf.put(new_cfg)
            
            # Apply dynamic update
            kramer.changeConfig(cf)
            
            # Verify existing caches DID NOT change
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            
            # Existing caches must remain unchanged
            assert cache.d == 1000
            assert cache.ml == 1000
            assert cache.pml == 1000
            assert cache.xl == 1000
            assert cache.pxl == 1000
            
            # Verify cache-type template DID change
            ctyp = receiverHby.db.kramCTYP.get("~")

            # Accept windows remain old (staged)
            assert ctyp.d == 1000
            assert ctyp.sl == 1000
            assert ctyp.ll == 1000
            assert ctyp.xl == 1000

            # Prune windows updated immediately
            assert ctyp.psl == 5000
            assert ctyp.pll == 5000
            assert ctyp.pxl == 5000
            
            # Advance time to complete staging
            clock.advance(5000)
            # kramer.reconcileConfig()

            # Existing cache STILL unchanged
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))

            assert cache.d == 1000
            assert cache.ml == 1000
            assert cache.pml == 1000
            assert cache.xl == 1000
            assert cache.pxl == 1000

            # Create a new message with the new cache values
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="ksn",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            ctyp2 = receiverHby.db.kramCTYP.get("~")
            # Accept windows updated
            assert ctyp2.sl == 5000
            assert ctyp2.ll == 5000
            assert ctyp2.xl == 5000

            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))

            # Assert the new cache uses the new values
            assert cache.mdt == stamp
            assert cache.d == 1000
            assert cache.ml == 5000
            assert cache.pml == 5000
            assert cache.xl == 5000
            assert cache.pxl == 5000


def test_new_cache_type(fakeHelpingClock):
    """
    Test Case 3 behavior when introducing a brand‑new cache‑type with larger
    accept/prune windows than the existing configuration.

    This test verifies the following invariants:

    1. **New cache-type detection**
       A new cache-type ("exn.R.route1") added to the configuration must be
       staged when its accept windows exceed those of the existing fallback "~"
       cache-type. The new cache-type must appear in `kramer._pending`.

    2. **Case 3 staging semantics**
       Before the Case‑3 delta expires:
         • Accept windows (sl, ll, xl) must remain equal to the smallest old
           accept windows (from "~").
         • Prune windows (psl, pll, pxl) must update immediately to the new
           values.

    3. **Message processing before delta expiration**
       • The TMSC entry must reflect staged accept windows and updated prune
         windows.

    4. **Delta expiration and reconciliation**
       After advancing the fake clock past the Case‑3 delta and calling
       `reconcileConfig()`:
         • The staged accept windows must be applied.
         • A new EXN message routed to "route1" must use the updated accept
           windows (5000/6000/7000).

    5. **Fallback behavior for unrelated routes**
       An EXN message routed to a different route ("offroad") must fall back to
       the "~" cache-type:
         • Accept windows must remain the fallback values (1000/2000/3000).
         • Prune windows must also reflect the fallback values.

    Overall, this test ensures that:
       • New cache-types are staged correctly under Case‑3 rules.
       • Accept/prune windows transition safely and deterministically.
       • Message processing respects staged vs. finalized configuration state.
    """
    # Instantiate the clock
    clock = fakeHelpingClock

    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="sender", base="test", salt=salt_sender, temp=True) as senderHby,
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):

        # Create single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1, transferable=True)

        # Create receiver hab
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1, transferable=True)

        # Load sender's ICP into receiver
        cross = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=cross)
        assert senderHab.pre in cross.kevers

        with openCF(name="kram", base="test", temp=True) as cf:
            
            # Old configuration only has the fallback or default cache-type ~
            old_cfg = {
                "kram": {
                    "enabled": True,
                    "caches": {
                        "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                    }
                }
            }

            # New configuration adds one cache-type with message-type.R.route
            new_cfg = {
                "kram": {
                    "enabled": True,
                    "caches": {
                        "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                        "exn.R.route1": [0, 5000, 6000, 7000, 5000, 6000, 7000],
                    }
                }
            }
            
            # Put the old config
            cf.put(old_cfg)

            # Instantiate Kramer and Kevery
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)
            
            # Update the config with the new config
            cf.put(new_cfg)
            kramer.changeConfig(cf)

            # Assert the new cache-type is pending
            assert "exn.R.route1" in kramer._pending

            # Use worst case scenario until delta passes
            exnCt = receiverHby.db.kramCTYP.get("exn.R.route1")

            # Accept window is unchanged until delta passes
            assert exnCt.sl == 1000
            assert exnCt.ll == 2000
            assert exnCt.xl == 3000
            
            # Pruning window is changed immediately
            assert exnCt.psl == 5000
            assert exnCt.pll == 6000
            assert exnCt.pxl == 7000

            # Initiate the exchange with a xip
            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)
            verfers = senderHab.kever.verfers

            # Test with seeded xip via kramit directly
            xip = exchept(sender=senderHab.pre,
                          receiver=receiverHab.pre,
                          route="route1",
                          stamp=stamp)

            # Sign xip
            sigers = senderHab.mgr.sign(ser=xip.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Call kramit directly (processMsg rejects xip)
            result = kramer.kramit(xip, **kwa)
            assert result is not None  # xip accepted

            # Create an exchange message with route1
            exn = exchange(sender=senderHab.pre,
                           receiver=receiverHab.pre,
                           xid=xip.said,
                           route="route1",
                           attributes=dict(n='5c'),
                           stamp=stamp)

            sigers = senderHab.mgr.sign(ser=exn.raw,
                                    verfers=senderHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Error raised due to lack of exchanger
            with pytest.raises(ValidationError):
                kvy.processMsg(exn, **kwa)

            # Assert tmsc entry created for exn
            cache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn.said))
            assert cache is not None

            # Assert the lag values are stil unchanged
            assert cache.ml == 1000
            assert cache.ml == exnCt.sl
            assert cache.xl == 3000
            assert cache.xl == exnCt.xl

            # Assert prune values changed immediately
            assert cache.pml == 5000
            assert cache.pml == exnCt.psl
            assert cache.pxl == 7000
            assert cache.pxl == exnCt.pxl

            # Advance time to delta + 1 sec
            delta = kramer._pending["exn.R.route1"]["delta"]
            clock.advance(milliseconds=delta, seconds=1)

            # Reconcile the config
            # kramer.reconcileConfig()

            # Send a new message with the new config
            stamp = helping.nowIso8601()

            # Create a new exn message
            exn = exchange(sender=senderHab.pre,
                           receiver=receiverHab.pre,
                           xid=xip.said,
                           route="route1",
                           attributes=dict(n='5c'),
                           stamp=stamp)

            sigers = senderHab.mgr.sign(ser=exn.raw,
                                    verfers=senderHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Error raised due to lack of exchanger
            with pytest.raises(ValidationError):
                kvy.processMsg(exn, **kwa)

             # Assert the new cache-type was processed and removed
            assert "exn.R.route1" not in kramer._pending

            # Assert new exn.R.route1 cache-type values
            exnCt = receiverHby.db.kramCTYP.get("exn.R.route1")

            # Assert values now reflect the new config
            assert exnCt.sl == 5000
            assert exnCt.ll == 6000
            assert exnCt.xl == 7000

            # Assert tmsc entry created for exn
            cache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn.said))
            assert cache is not None

            # Assert the window lag values are the new exn.R.route1 values
            assert cache.ml == 5000
            assert cache.ml == exnCt.sl
            assert cache.xl == 7000
            assert cache.xl == exnCt.xl


            # Create a new exn message that uses a different route
            exn = exchange(sender=senderHab.pre,
                                    receiver=receiverHab.pre,
                                    xid=xip.said,
                                    route="offroad",
                                    attributes=dict(n='5c'),
                                    stamp=stamp)

            sigers = senderHab.mgr.sign(ser=exn.raw,
                                    verfers=senderHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Error raised due to lack of exchanger
            with pytest.raises(ValidationError):
                kvy.processMsg(exn, **kwa)

            # Assert tmsc entry created for exn
            cache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn.said))
            assert cache is not None

            # Get the fallback cache
            fbCt = receiverHby.db.kramCTYP.get("~")

            # Assert the window lag values are the fallback values
            assert cache.ml == 1000
            assert cache.ml == fbCt.sl

            assert cache.xl == 3000
            assert cache.xl == fbCt.xl

            assert cache.pml == 1000
            assert cache.pml == fbCt.psl

            assert cache.pxl == 3000
            assert cache.pxl == fbCt.pxl


def test_multiple_new_cache_type(fakeHelpingClock):
    """
    Test Case‑3 staging behavior when multiple new cache‑types (“exn” and “qry”)
    are introduced simultaneously, each with accept/prune windows larger than
    the existing fallback cache‑type (“~”).

    This test verifies the following invariants:

    1. **Detection of multiple new cache‑types**
       Both “exn” and “qry” must appear in `kramer._pending` after the
       configuration change, since their accept windows exceed those of the
       fallback cache-type.

    2. **Case‑3 staging semantics for each new cache‑type**
       Before the Case‑3 delta expires:
         • Accept windows (sl, ll, xl) for both “exn” and “qry” must remain
           equal to the smallest old accept windows (from “~”).
         • Prune windows (psl, pll, pxl) must update immediately to the new
           values for each cache‑type.

    3. **Message classification under staged configuration**
       • A `query` message with any route must be classified under the “qry”
         cache‑type and use staged accept windows and updated prune windows.
       • An `exn` message (via xip → exn flow) must be classified under the
         “exn” cache‑type and use staged accept windows and updated prune
         windows.
       • Both message types must create the appropriate cache entries
         (MSGC for queries, TMSC for EXN messages).

    4. **Delta expiration and reconciliation**
       After advancing the fake clock past the Case‑3 delta and calling
       `reconcileConfig()`:
         • The staged accept windows for both “exn” and “qry” must be applied.
         • New messages must reflect the updated accept windows:
               qry: sl=3000, xl=5000
               exn: sl=4000, xl=6000

    5. **Route‑based classification remains correct**
       • Query messages with arbitrary routes (e.g., “ksn”) must still map to
         the “qry” cache‑type.
       • EXN messages with arbitrary routes (e.g., “route1”) must still map to
         the “exn” cache‑type.

    Overall, this test ensures that:
       • Multiple new cache‑types are staged correctly under Case‑3 rules.
       • Accept/prune windows transition safely and deterministically.
       • Message processing respects staged vs. finalized configuration state.
       • Coverage‑based classification remains stable across the transition.
    """

    clock = fakeHelpingClock

    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="sender", base="test", salt=salt_sender, temp=True) as senderHby,
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):

        old_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                }
            }
        }
        # (d, sl, ll, xl, psl, pll, pxl)
        new_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                    "exn": [0, 4000, 5000, 6000, 4000, 5000, 6000],
                    "qry": [0, 3000, 4000, 5000, 3000, 4000, 5000],
                }
            }
        }

        # Create transferable single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1, transferable=True)
        
        # Create receiver hab
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1, transferable=True)

        # Load sender's ICP into receiver
        cross = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=cross)
        assert senderHab.pre in cross.kevers

        with openCF(name="kram", base="test", temp=True) as cf:
            cf.put(old_cfg)
            kramer = Kramer(db=receiverHby.db, cf=cf)

            # Create Kevery 
            kvy = Kevery(db=receiverHby.db, lax=False, local=False, kramer=kramer)

            cf.put(new_cfg)
            kramer.changeConfig(cf)

            assert "exn" in kramer._pending
            assert "qry" in kramer._pending

            # Assert exn cache-type value
            exnCt = receiverHby.db.kramCTYP.get("exn")

            # Use the worst case scenario
            # Accept window is unchanged untill delta passes
            assert exnCt.sl == 1000
            assert exnCt.ll == 2000
            assert exnCt.xl == 3000

            # Pruning window is changed immediately
            assert exnCt.psl == 4000
            assert exnCt.pll == 5000
            assert exnCt.pxl == 6000

            # Assert qry cache-type values
            qryCt = receiverHby.db.kramCTYP.get("qry")
            
            # Use the worst case scenario
            # Accept window is unchanged untill delta passes
            assert qryCt.sl == 1000
            assert qryCt.ll == 2000
            assert qryCt.xl == 3000

            # Pruning window is changed immediately
            assert qryCt.psl == 3000
            assert qryCt.pll == 4000
            assert qryCt.pxl == 5000


            # Create a query message with a route, should still be part of query cache-type
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="ksn",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are still unchanged
            assert cache.ml == 1000
            assert cache.ml == qryCt.sl
            assert cache.xl == 3000
            assert cache.xl == qryCt.xl
            
            # Assert pruning values
            assert cache.pml == 3000
            assert cache.pml == qryCt.psl
            assert cache.pxl == 5000
            assert cache.pxl == qryCt.pxl

            # Create an ixp message
            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)
            verfers = senderHab.kever.verfers

            # Test with seeded xip via kramit directly
            xip = exchept(sender=senderHab.pre,
                          receiver=receiverHab.pre,
                          route="route1",
                          stamp=stamp)

            # Sign xip
            sigers = senderHab.mgr.sign(ser=xip.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Call kramit directly (processMsg rejects xip)
            result = kramer.kramit(xip, **kwa)
            assert result is not None  # xip accepted

            # Create an exchange message with a route, still falls in the broader exn cache-type
            exn = exchange(sender=senderHab.pre,
                           receiver=receiverHab.pre,
                           xid=xip.said,
                           route="route1",
                           attributes=dict(n='5c'),
                           stamp=stamp)

            sigers = senderHab.mgr.sign(ser=exn.raw,
                                    verfers=senderHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Error raised due to lack of exchanger
            with pytest.raises(ValidationError):
                kvy.processMsg(exn, **kwa)

            # Assert tmsc entry created for exn
            cache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn.said))
            assert cache is not None
            
            # Assert lag values are still unchanged
            assert cache.ml == 1000
            assert cache.ml == exnCt.sl
            assert cache.xl == 3000
            assert cache.xl == exnCt.xl
            
            # Assert pruning values
            assert cache.pml == 4000
            assert cache.pml == exnCt.psl
            assert cache.pxl == 6000
            assert cache.pxl == exnCt.pxl

            # Advance time to delta + 1 sec, delta for qry and exn are the same
            delta = kramer._pending["qry"]["delta"]
            clock.advance(milliseconds=delta, seconds=1)

            # Reconcile the config
            # kramer.reconcileConfig()

            # Create a query message with a route, should still be part of query cache-type
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="ksn",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert new qry cache-type values
            qryCt = receiverHby.db.kramCTYP.get("qry")
            
            # Assert values now reflect the new config
            assert qryCt.sl == 3000
            assert qryCt.ll == 4000
            assert qryCt.xl == 5000

            # Assert exn cache-type value
            exnCt = receiverHby.db.kramCTYP.get("exn")

            # Assert values now reflect the new config
            assert exnCt.sl == 4000
            assert exnCt.ll == 5000
            assert exnCt.xl == 6000


            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert window lag values changed
            assert cache.ml == 3000
            assert cache.ml == qryCt.sl
            assert cache.xl == 5000
            assert cache.xl == qryCt.xl
            
            # Create an exchange message
            exn = exchange(sender=senderHab.pre,
                           receiver=receiverHab.pre,
                           xid=xip.said,
                           route="route1",
                           attributes=dict(n='5c'),
                           stamp=stamp)

            sigers = senderHab.mgr.sign(ser=exn.raw,
                                    verfers=senderHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Error raised due to lack of exchanger
            with pytest.raises(ValidationError):
                kvy.processMsg(exn, **kwa)

            # Assert tmsc entry created for exn
            cache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn.said))
            assert cache is not None
            
            # Assert window lag values changed
            assert cache.ml == 4000
            assert cache.ml == exnCt.sl
            assert cache.xl == 6000
            assert cache.xl == exnCt.xl


def test_merge_cache_types(fakeHelpingClock):
    """
    Test Case‑3 behavior when multiple route‑specific cache‑types
    (“qry.R.logs” and “qry.R.ksn”) are merged into a single broader
    cache‑type (“qry”) whose accept/prune windows are larger than any of the
    old per‑route cache‑types.

    This test validates the following invariants:

    1. **Detection of a merge as a Case‑3 expansion**
       The new “qry” cache‑type covers all patterns previously covered by
       “qry.R.logs” and “qry.R.ksn”. 
       Because its accept windows are larger than the old ones, the merge must be staged:
           • “qry” must appear in `kramer._pending`.

    2. **Staged accept‑window behavior**
       Before the Case‑3 delta expires:
         • Accept windows (sl, ll, xl) for “qry” must remain equal to the
           smallest old accept windows (from the fallback “~”).
         • Prune windows (psl, pll, pxl) must update immediately to the new
           merged values (6000/7000/8000).

    3. **Message classification during the staging period**
       Messages routed to either “ksn” or “logs” must:
         • Continue using their old per‑route accept windows
               ksn: sl=2000, xl=4000
               logs: sl=1500, xl=3500
         • Use the new merged prune windows (6000/7000/8000).
       This ensures that merging does not retroactively widen accept windows
       before the delta expires.

    4. **Delta expiration and reconciliation**
       After advancing the fake clock past the Case‑3 delta and calling
       `reconcileConfig()`:
         • The staged accept windows for “qry” must be applied.
         • New messages routed to either “ksn” or “logs” must now use the
           merged accept windows:
               sl=6000, xl=8000.

    5. **Route‑based classification remains correct**
       Even after merging:
         • Messages with route “ksn” or “logs” must still classify under the
           “qry” cache‑type.
         • Their lag values must reflect the correct staged or finalized
           windows depending on whether the delta has expired.

    Overall, this test ensures that:
       • Merging multiple cache‑types into a broader one triggers Case‑3
         staging correctly.
       • Accept/prune windows transition safely and deterministically.
       • Old per‑route semantics remain valid until the staging delta expires.
       • Message processing remains consistent across the merge boundary.
    """
    clock = fakeHelpingClock

    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="sender", base="test", salt=salt_sender, temp=True) as senderHby,
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):

        old_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                    "qry.R.logs": [0, 1500, 2500, 3500, 1500, 2500, 3500],
                    "qry.R.ksn": [0, 2000, 3000, 4000, 2000, 3000, 4000],
                }
            }
        }

        new_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                    "qry": [0, 6000, 7000, 8000, 6000, 7000, 8000],
                }
            }
        }

        # Create transferable single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1, transferable=True)
        
        # Create receiver hab
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1, transferable=True)

        # Load sender's ICP into receiver
        cross = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=cross)
        assert senderHab.pre in cross.kevers

        with openCF(name="kram", base="test", temp=True) as cf:
            cf.put(old_cfg)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            
            # Create Kevery 
            kvy = Kevery(db=receiverHby.db, lax=False, local=False, kramer=kramer)
            
            cf.put(new_cfg)
            kramer.changeConfig(cf)

            # Assert old cache-type are removed
            assert receiverHby.db.kramCTYP.get("qry.R.ksn") is None
            assert receiverHby.db.kramCTYP.get("qry.R.logs") is None

            # Assert new "qry" cache-type is in pending
            assert "qry" in kramer._pending

            # Assert qry cache-type values
            qryCt = receiverHby.db.kramCTYP.get("qry")
            
            # Use the worst case scenario which in this case is the fallback ~
            # Accept window is unchanged untill delta passes
            assert qryCt.sl == 1000
            assert qryCt.ll == 2000
            assert qryCt.xl == 3000

            # Pruning windows are immediately changed
            assert qryCt.psl == 6000
            assert qryCt.pll == 7000
            assert qryCt.pxl == 8000

            # Create a query message with the ksn route
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="ksn",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are from the worst-case scenario
            assert cache.ml == 1000
            assert cache.xl == 3000
            
            # Assert pruning values are from the new qry cache-type
            assert cache.pml == 6000
            assert cache.pml == qryCt.psl
            assert cache.pxl == 8000
            assert cache.pxl == qryCt.pxl

            # Create a query message with the logs route
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="logs",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are from the worst-case scenario
            assert cache.ml == 1000
            assert cache.xl == 3000
            
            # Assert pruning values are from the new qry cache-type
            assert cache.pml == 6000
            assert cache.pml == qryCt.psl
            assert cache.pxl == 8000
            assert cache.pxl == qryCt.pxl

            # Advance time to delta + 1 sec
            delta = kramer._pending["qry"]["delta"]
            clock.advance(milliseconds=delta, seconds=1)

            # Reconcile config
            # kramer.reconcileConfig()
            
            # Create a new qry message with the ksn route 
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="ksn",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

             # Assert "qry" was processed and removed
            assert "qry" not in kramer._pending

            # Assert qry cache-type values
            qryCt = receiverHby.db.kramCTYP.get("qry")
            
            # Assert accept window now reflects the new config
            assert qryCt.sl == 6000
            assert qryCt.ll == 7000
            assert qryCt.xl == 8000

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are updated to the new qry cache-type
            assert cache.ml == 6000
            assert cache.ml == qryCt.sl
            assert cache.xl == 8000
            assert cache.xl == qryCt.xl


            # Create a new qry message with the logs route 
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="logs",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are updated to the new qry cache-type
            assert cache.ml == 6000
            assert cache.ml == qryCt.sl
            assert cache.xl == 8000
            assert cache.xl == qryCt.xl


def test_modify_cache_types(fakeHelpingClock):
    """
    Tests dynamic reconfiguration when two cache‑types under the same prefix are
    updated with mixed semantics:

    - qry.R.logs increases (Case‑2): prune windows update immediately, accept
    windows are staged, and a pending entry is created with the correct unified
    delta.

    - qry.R.ksn decreases (Case‑1): all windows update immediately and no pending
    entry is created.

    The test also verifies:
    - correct unified delta computation (max of Case‑2 and Case‑3 deltas),
    - correct classification behavior before and after delta,
    - correct reconciliation behavior once delta has elapsed,
    - correct message‑cache creation using staged vs. final windows.
    """

    clock = fakeHelpingClock

    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="sender", base="test", salt=salt_sender, temp=True) as senderHby,
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):

        old_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                    "qry.R.logs": [0, 1500, 2500, 3500, 1500, 2500, 3500],
                    "qry.R.ksn": [0, 2000, 3000, 4000, 2000, 3000, 4000],
                }
            }
        }

        # New configuration increases logs route lag values and decreases ksn route values
        new_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                    "qry.R.logs": [0, 3500, 4500, 5500, 3500, 4500, 6500],
                    "qry.R.ksn": [0, 1500, 2500, 3500, 1500, 2500, 3500],
                }
            }
        }

        # Create transferable single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1, transferable=True)
        
        # Create receiver hab
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1, transferable=True)

        # Load sender's ICP into receiver
        cross = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=cross)
        assert senderHab.pre in cross.kevers

        with openCF(name="kram", base="test", temp=True) as cf:
            cf.put(old_cfg)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            
            # Create Kevery 
            kvy = Kevery(db=receiverHby.db, lax=False, local=False, kramer=kramer)
            
            cf.put(new_cfg)
            kramer.changeConfig(cf)


            # Assert qry.R.logs cache-type is in pending
            assert "qry.R.logs" in kramer._pending

            # Assert qry.R.ksn is not in pending since it's decreasing, pending is not created
            assert "qry.R.ksn" not in kramer._pending

            # Create a query message with the ksn route
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="ksn",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert qry.R.logs cache-type values
            qryCtLgs = receiverHby.db.kramCTYP.get("qry.R.logs")
            
            # Use the worst case scenario which in this case is ksn route
            # Accept window is unchanged untill delta passes
            assert qryCtLgs.sl == 1500
            assert qryCtLgs.ll == 2500
            assert qryCtLgs.xl == 3500

            # Pruning windows are immediately changed
            assert qryCtLgs.psl == 3500
            assert qryCtLgs.pll == 4500
            assert qryCtLgs.pxl == 6500


            # Assert qry.R.ksn cache-type values
            qryCtKsn = receiverHby.db.kramCTYP.get("qry.R.ksn")

            # Accept window are changed immediately because qry.R.ksn is a case 1
            assert qryCtKsn.sl == 1500
            assert qryCtKsn.ll == 2500
            assert qryCtKsn.xl == 3500

            # Pruning windows are immediately changed
            assert qryCtKsn.psl == 1500
            assert qryCtKsn.pll == 2500

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are from the new qry.R.ksn cache-type
            assert cache.ml == 1500
            assert cache.xl == 3500
            
            # Assert pruning values are from the new qry.R.ksn cache-type
            assert cache.pml == 1500
            assert cache.pml == qryCtKsn.psl
            assert cache.pxl == 3500
            assert cache.pxl == qryCtKsn.pxl


            # Create a query message with the logs route
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="logs",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are from the worst-case scenario
            assert cache.ml == 1500
            assert cache.xl == 3500
            
            # Assert pruning values are from the new cache-type
            assert cache.pml == 3500
            assert cache.pml == qryCtLgs.psl
            assert cache.pxl == 6500
            assert cache.pxl == qryCtLgs.pxl

            # Advance time to delta + 1 sec
            # Note that pending only contains qry.R.logs because it's the only
            # cache-type that increases
            delta = kramer._pending["qry.R.logs"]["delta"]

            # Assert unified delta was computed correctly
            pend = kramer._pending["qry.R.logs"]

            # Case‑2 delta: increases in sl/ll/xl
            expected_case2 = max(
                3500 - 1500,   # sl increase
                4500 - 2500,   # ll increase
                5500 - 3500,   # xl increase
            )

            # Case‑3 delta: no coverage expansion in this test
            expected_case3 = 0

            expected_unified = max(expected_case2, expected_case3)

            assert delta == expected_unified

            clock.advance(milliseconds=delta, seconds=1)

            # Reconcile config
            # kramer.reconcileConfig()
            
            # Create a new qry message with the logs route
            stamp = helping.nowIso8601()
            msg = query(pre=senderHab.pre,
                        route="logs",
                        query=dict(i=senderHab.pre, src=senderHab.pre),
                        stamp=stamp,
                        pvrsn=Vrsn_2_0)

            # Sign with sender's keys
            sigers = senderHab.mgr.sign(ser=msg.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, sigers)])

            kvy.processMsg(msg, **kwa)
            
            # Assert "qry" was processed and removed
            assert "qry.R.logs" not in kramer._pending

            # Assert qry cache-type values
            qryCtLgs = receiverHby.db.kramCTYP.get("qry.R.logs")
            
            # Assert accept window now reflects the new config
            assert qryCtLgs.sl == 3500
            assert qryCtLgs.ll == 4500
            assert qryCtLgs.xl == 5500

            # Assert cache created
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            
            # Assert lag values are updated to the new qry cache-type
            assert cache.ml == 3500
            assert cache.ml == qryCtLgs.sl
            assert cache.xl == 5500
            assert cache.xl == qryCtLgs.xl


def test_coverage_hole():
    """
    Test that Kramer rejects configuration changes that introduce a coverage hole.

    This test verifies the core Case‑3 invariant that:
        **All patterns covered by the old configuration must remain covered
        in the new configuration. No coverage holes are allowed.**

    Scenario:
        • The old configuration contains only the fallback cache-type "~",
          which semantically covers (ANY, ANY) — i.e., every possible
          (message-type, route) pattern.
        • The new configuration replaces "~" with a single cache-type "exn",
          which only covers (EXN, ANY).

    Expected behavior:
        • Because the new configuration no longer covers patterns such as
          (QRY, ANY), (RLY, ANY), or any other non‑EXN message types,
          a coverage hole is introduced.
        • `_validateCoverage()` must detect this hole.
        • `changeConfig()` must raise an exception and refuse to apply the
          unsafe configuration.

    This test ensures that:
        • Coverage graphs are computed correctly.
        • Coverage holes are detected deterministically.
        • Kramer never transitions into a configuration that would leave
          previously valid message patterns without a corresponding cache-type.
    """

    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (
        openHby(name="receiver", base="test", salt=salt_receiver, temp=True) as receiverHby
    ):
        # Old configuration has a default fallback: ANY (message type) ANY (route) cache-type
        old_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "~": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                }
            }
        }

        # New configuration only has a (EXN, ANY) cache-type
        new_cfg = {
            "kram": {
                "enabled": True,
                "caches": {
                    "exn": [0, 1000, 2000, 3000, 1000, 2000, 3000],
                }
            }
        }

        with openCF(name="kram", base="test", temp=True) as cf:
            cf.put(old_cfg)
            kramer = Kramer(db=receiverHby.db, cf=cf)

            cf.put(new_cfg)

            # Raises an error for coverage hole
            with pytest.raises(Exception):
                kramer.changeConfig(cf)


def test_pruning_messages_single_key(fakeHelpingClock):
    """
    Test pruning behavior for single-key sender messages.

    Covers: pruning of messages with different timestamps, ensuring pruning is
    based on each message's own timestamp and not affected by other messages from the same sender.

    Steps:
    - accept a message
    - accept a message from the same sender with a later timestamp
    - Advance time to trigger pruning for the 1st message, assert 2nd message is still cached
    - Advance time to trigger pruning for the 2nd message
    """

    # Instantiate Clock
    clock = fakeHelpingClock

    # Assert the clock
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    # Setup sender/receiver
    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="sender", base="test", salt=salt_sender) as senderHby,
          openHby(name="receiver", base="test", salt=salt_receiver) as receiverHby):

        # Create transferable single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1, transferable=True)

        # Create receiver hab
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1, transferable=True)

        # Load sender's ICP into receiver
        cross = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=cross)
        assert senderHab.pre in cross.kevers

        # Create Kramer with config
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            assert kramer.enabled

            # Create Kevery
            kvy = Kevery(db=receiverHby.db, lax=False, local=False, kramer=kramer)

            # Setup Doist with PruneDoer
            tock = 1
            limit = 1.0

            # Create PruneDoer
            pruneDoer = Pruner(kramer, tock)

            doist = doing.Doist(tock=tock, limit=limit)
            deeds = doist.enter(doers=[pruneDoer])

            # Step 1: Accept a fresh message
            earlyStamp = helping.nowIso8601()
            assert earlyStamp == "2021-01-01T00:00:00.000000+00:00"

            earlyMsg = query(
                pre=senderHab.pre,
                route="ksn",
                query=dict(i=senderHab.pre, src=senderHab.pre),
                stamp=earlyStamp,
                pvrsn=Vrsn_2_0,
            )

            # Sign with sender's keys
            earlySigers = senderHab.mgr.sign(
                ser=earlyMsg.raw,
                verfers=senderHab.kever.verfers,
                indexed=True,
            )
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, earlySigers)])

            # Process message, should be accepted and cached
            kvy.processMsg(earlyMsg, **kwa)

            # Run the doist to process pruning (though it shouldn't prune anything yet)
            doist.recur(deeds=deeds)

            # Cache must exist
            earlyCache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, earlyMsg.said))
            assert earlyCache is not None
            assert earlyCache.mdt == earlyStamp
            assert earlyCache.d == 1000   # drift = 1s
            assert earlyCache.ml == 5000     # short lag = 5s
            assert earlyCache.pml == 5000    # short prune lag = 5s

            # Step 2: send another message at a later time
            # The timeliness window allows 1s drift (d = 1000ms) so 1s after is still inside
            # Advance time by 1s
            clock.advance(seconds=1)

            rdtLater = helping.nowIso8601()
            assert rdtLater == "2021-01-01T00:00:01.000000+00:00"

            # Create a new message with the later timestamp
            laterMsg = query(
                pre=senderHab.pre,
                route="ksn",
                query=dict(i=senderHab.pre, src=senderHab.pre),
                stamp=rdtLater,
                pvrsn=Vrsn_2_0,
            )
            laterSigers = senderHab.mgr.sign(
                ser=laterMsg.raw,
                verfers=senderHab.kever.verfers,
                indexed=True,
            )
            prefixer = Prefixer(qb64=senderHab.pre)
            kwa = dict(ssgs=[(prefixer, laterSigers)])

            # Process the later message
            kvy.processMsg(laterMsg, **kwa)

            # Assert later message is cached with its own timestamp
            laterCache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, laterMsg.said))
            assert laterCache is not None
            assert laterCache.mdt == rdtLater

            # Advance time
            clock.advance(seconds=4)
            assert helping.nowIso8601() == "2021-01-01T00:00:05.000000+00:00"

            # Run doist
            doist.recur(deeds=deeds)

            # Both entries must still exist because both messages are still within their respective pruning windows.
            earlyCache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, earlyMsg.said))
            assert earlyCache is not None
            assert earlyCache.mdt == earlyStamp

            laterCache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, laterMsg.said))
            assert laterCache is not None
            assert laterCache.mdt == rdtLater

            # Step 3: increase the time to trigger pruning for the first messsage but not the second message
            # Increase the time to passed to 6.1s which is just past the 5s drift + 1s prune lag = 6s total
            # for the first message, but the second message is still within its pruning window
            clock.advance(seconds=1.1)
            assert helping.nowIso8601() == "2021-01-01T00:00:06.100000+00:00"

            # Recur to trigger pruning of the 1st message
            doist.recur(deeds=deeds)

            # First message must now be pruned
            assert receiverHby.db.kramMSGC.get(keys=(senderHab.pre, earlyMsg.said)) is None

            # Second message is still here because of its later timestamp
            assert receiverHby.db.kramMSGC.get(keys=(senderHab.pre, laterMsg.said)) is not None

            # Step 4: Advance time to prune the second message
            clock.advance(seconds=1)
            assert helping.nowIso8601() == "2021-01-01T00:00:07.100000+00:00"

            # Run doist
            doist.recur(deeds=deeds)

            # Second message must now be pruned
            assert receiverHby.db.kramMSGC.get(keys=(senderHab.pre, laterMsg.said)) is None

            # Close doist
            doist.exit()

        """Done Test"""


def test_pruning_messages_multi_key(fakeHelpingClock):
    """Test pruning with multi-key sender (asmk auth type, 2-of-3 threshold) and nont auth attachments.

    Covers: partial accumulation where threshold is never met,
    pruning is called and cleans up cache and attachments.

    Steps:
    - Multi-key message created threshold is not met yet, cache created, partials populated
    - Threshold is never met, advance time past the exchange pruning window
    - Assert all entries for cache, partials and attachments are deleted
    """

    # Step 1: Setup
    # Instantiate Clock
    clock = fakeHelpingClock

    # Check the clock
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    salt1 = Salter(raw=b'0123456789abcdef').qb64
    salt2 = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="mkSender", base="test", salt=salt1) as senderHby,
          openHby(name="mkReceiver", base="test", salt=salt2) as receiverHby):

        # Create 2-of-3 multi-key sender
        senderHab = senderHby.makeHab(name="mkSender", isith='2', icount=3,
                                      transferable=True)
        assert len(senderHab.kever.verfers) == 3

        # Create receiver hab for db context
        receiverHby.makeHab(name="mkReceiver", isith='1', icount=1,
                            transferable=True)

        # Cross-feed sender ICP to receiver
        crossKvy = Kevery(db=receiverHby.db, lax=False, local=False)
        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=crossKvy)
        assert senderHab.pre in crossKvy.kevers

        # Create Kevery with kramer
        with openCF(name="mkKram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False,
                                  kramer=kramer)

            # Setup Doist with PruneDoer
            tock = 1
            limit = 1

            # Create PruneDoer
            pruneDoer = Pruner(kramer, tock)

            # Create Doist
            doist = doing.Doist(tock=tock, limit=limit, real=True)
            deeds = doist.enter(doers=[pruneDoer])

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)
            verfers = senderHab.kever.verfers

            def signMsg(msg):
                return senderHab.mgr.sign(ser=msg.raw, verfers=verfers,
                                          indexed=True)

            # Partial accumulation to ensure partial sigs are populated

            msg = query(pre=senderHab.pre,
                                   route="ksn",
                                   query=dict(i=senderHab.pre, src=senderHab.pre),
                                   stamp=stamp,
                                   pvrsn=Vrsn_2_0)
            allSigers = signMsg(msg)

            # Build non-auth attachments to include in kwa
            partialKey = (senderHab.pre, msg.said)
            senderKever = receiverHby.db.kevers[senderHab.pre]
            seqner = Seqner(sn=senderKever.sner.num)
            saider = Saider(qb64=senderKever.serder.said)
            diger = Diger(ser=msg.raw)

            # trqs: trans receipt quadruple (prefixer, seqner, saider, siger)
            trqs = [(prefixer, seqner, saider, allSigers[0])]

            # tsgs: trans last sig group (prefixer, seqner, saider, [sigers])
            tsgs = [(prefixer, seqner, saider, [allSigers[0]])]

            # sscs: first seen seal couple (seqner, saider) issuing or delegating
            sscs = [(seqner, saider)]

            # ssts: source seal triple (prefixer, seqner, saider) issued or delegated
            ssts = [(prefixer, seqner, saider)]

            # frcs: first seen replay couple (seqner, dater)
            firner = Seqner(sn=0)
            dater = Dater(dts=stamp)
            frcs = [(firner, dater)]

            # tdcs: typed digest seal couple (verser, diger)
            verser = Verser(pvrsn=Vrsn_2_0)
            tdcs = [(verser, diger)]

            # ptds: pathed stream (raw bytes)
            ptds = [b'\x00\x01\x02\x03']

            # bsqs: blind state quadruple (diger, noncer, noncer, labeler)
            noncer0 = Noncer()
            noncer1 = Noncer()
            labeler = Labeler(label='test')
            bsqs = [(diger, noncer0, noncer1, labeler)]

            # bsss: bound state sextuple (diger, noncer, noncer, labeler, number, noncer)
            number = Number(num=1)
            noncer2 = Noncer()
            bsss = [(diger, noncer0, noncer1, labeler, number, noncer2)]

            # tmqs: type media quadruple (diger, noncer, labeler, texter)
            texter = Texter(text='application/json')
            tmqs = [(diger, noncer0, labeler, texter)]


            # First delivery with 1 sig (below threshold) + non-auth attachments

            kwa = dict(ssgs=[(prefixer, [allSigers[0]])],
                       trqs=trqs, tsgs=tsgs, sscs=sscs, ssts=ssts,
                       frcs=frcs, tdcs=tdcs, ptds=ptds,
                       bsqs=bsqs, bsss=bsss, tmqs=tmqs)

            kvy.processMsg(msg, **kwa)

            # Run the doist to process pruning (it shouldn't prune anything yet)
            doist.recur(deeds=deeds)

            # Assert msgc cache created for partial sigs
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.d == 1000   # drift = 1s
            assert cache.ml == 60000     # message long lag = 60s
            assert cache.pml == 60000    # message long prune lag = 60s

            # Assert that partial DBs are populated
            pmkm = receiverHby.db.kramPMKM.get(keys=(senderHab.pre, msg.said))
            assert pmkm is not None
            pmks = receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg.said))
            assert pmks is not None
            assert len(pmks) == 1
            pmsk = receiverHby.db.kramPMSK.get(keys=(senderHab.pre, msg.said))
            assert pmsk is not None

            # All non-auth attachment dbs populated
            assert len(receiverHby.db.kramTRQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTSGS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSTS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramFRCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTDCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramPTDS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSSS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTMQS.get(keys=partialKey)) == 1

            # No cue generated because threshold not met
            assert len(kvy.cues) == 0

            # Signatures never come, advance time to pruning
            pml = cache.pml/1000 # convert pml to seconds
            d = cache.d/1000    # convert d to seconds
            delta = pml + d + 0.1    # .1s outside the pruning window

            clock.advance(seconds=delta)
            assert helping.nowIso8601() == "2021-01-01T00:01:01.100000+00:00"

            doist.recur(deeds=deeds)

            # Assert cache and partials got cleaned up
            assert receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said)) is None
            assert receiverHby.db.kramPMKM.get(keys=(senderHab.pre, msg.said)) is None
            assert receiverHby.db.kramPMKS.get(keys=(senderHab.pre, msg.said)) == []
            assert receiverHby.db.kramPMSK.get(keys=(senderHab.pre, msg.said)) is None

            # Non auth attachments got cleaned up
            assert receiverHby.db.kramTRQS.get(keys=partialKey) == []
            assert receiverHby.db.kramTSGS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSCS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSTS.get(keys=partialKey) == []
            assert receiverHby.db.kramFRCS.get(keys=partialKey) == []
            assert receiverHby.db.kramTDCS.get(keys=partialKey) == []
            assert receiverHby.db.kramPTDS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSQS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSSS.get(keys=partialKey) == []
            assert receiverHby.db.kramTMQS.get(keys=partialKey) == []

            # Happy path, attachments pruned after threshold is met
            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)

            msg = query(pre=senderHab.pre,
                                 route="ksn",
                                 query=dict(i=senderHab.pre, src=senderHab.pre),
                                 stamp=stamp,
                                 pvrsn=Vrsn_2_0)
            allSigers = senderHab.mgr.sign(ser=msg.raw,
                                           verfers=senderHab.kever.verfers,
                                           indexed=True)

            partialKey = (senderHab.pre, msg.said)

            # Build non-auth attachments to include in kwa

            senderKever = receiverHby.db.kevers[senderHab.pre]
            seqner = Seqner(sn=senderKever.sner.num)
            saider = Saider(qb64=senderKever.serder.said)
            diger = Diger(ser=msg.raw)

            # trqs: trans receipt quadruple (prefixer, seqner, saider, siger)
            trqs = [(prefixer, seqner, saider, allSigers[0])]

            # tsgs: trans last sig group (prefixer, seqner, saider, [sigers])
            tsgs = [(prefixer, seqner, saider, [allSigers[0]])]

            # sscs: first seen seal couple (seqner, saider) issuing or delegating
            sscs = [(seqner, saider)]

            # ssts: source seal triple (prefixer, seqner, saider) issued or delegated
            ssts = [(prefixer, seqner, saider)]

            # frcs: first seen replay couple (seqner, dater)
            firner = Seqner(sn=0)
            dater = Dater(dts=stamp)
            frcs = [(firner, dater)]

            # tdcs: typed digest seal couple (verser, diger)
            verser = Verser(pvrsn=Vrsn_2_0)
            tdcs = [(verser, diger)]

            # ptds: pathed stream (raw bytes)
            ptds = [b'\x00\x01\x02\x03']

            # bsqs: blind state quadruple (diger, noncer, noncer, labeler)
            noncer0 = Noncer()
            noncer1 = Noncer()
            labeler = Labeler(label='test')
            bsqs = [(diger, noncer0, noncer1, labeler)]

            # bsss: bound state sextuple (diger, noncer, noncer, labeler, number, noncer)
            number = Number(num=1)
            noncer2 = Noncer()
            bsss = [(diger, noncer0, noncer1, labeler, number, noncer2)]

            # tmqs: type media quadruple (diger, noncer, labeler, texter)
            texter = Texter(text='application/json')
            tmqs = [(diger, noncer0, labeler, texter)]


            # First delivery with 1 sig (below threshold) + non-auth attachments

            kwa = dict(ssgs=[(prefixer, [allSigers[0]])],
                       trqs=trqs, tsgs=tsgs, sscs=sscs, ssts=ssts,
                       frcs=frcs, tdcs=tdcs, ptds=ptds,
                       bsqs=bsqs, bsss=bsss, tmqs=tmqs)
            kvy.processMsg(msg, **kwa)

            # Assert msgc cache created for partial sigs
            cache = receiverHby.db.kramMSGC.get(keys=(senderHab.pre, msg.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.d == 1000   # drift = 1s
            assert cache.ml == 60000     # message long lag = 60s
            assert cache.pml == 60000    # message long prune lag = 60s

            # Threshold not met, partials populated
            assert receiverHby.db.kramPMKM.get(keys=partialKey) is not None
            pmks = receiverHby.db.kramPMKS.get(keys=partialKey)
            assert len(pmks) == 1

            # All non-auth attachment dbs populated
            assert len(receiverHby.db.kramTRQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTSGS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramSSTS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramFRCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTDCS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramPTDS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSQS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramBSSS.get(keys=partialKey)) == 1
            assert len(receiverHby.db.kramTMQS.get(keys=partialKey)) == 1

            assert len(kvy.cues) == 0

            # Second delivery with 2nd sig meets threshold
            # Non-auth attachments should persist (pruner responsibility)

            kwa2 = dict(ssgs=[(prefixer, [allSigers[2]])],
                        trqs=trqs, tsgs=tsgs, sscs=sscs, ssts=ssts,
                        frcs=frcs, tdcs=tdcs, ptds=ptds,
                        bsqs=bsqs, bsss=bsss, tmqs=tmqs)
            kvy.processMsg(msg, **kwa2)

            # Threshold met, cue generated
            assert len(kvy.cues) > 0
            cue = kvy.cues.popleft()
            assert cue["kin"] == "reply"

            # Non-auth attachments persist
            assert len(receiverHby.db.kramTRQS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramTSGS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramSSCS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramSSTS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramFRCS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramTDCS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramPTDS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramBSQS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramBSSS.get(keys=partialKey)) >= 1
            assert len(receiverHby.db.kramTMQS.get(keys=partialKey)) >= 1

            # Advance time past pruning window
            pml = cache.pml/1000 # convert pml to seconds
            d = cache.d/1000    # convert d to seconds
            delta = pml + d + 0.1    # .1s outside the pruning window

            clock.advance(seconds=delta)
            doist.recur(deeds=deeds)

            # Non auth attachments got cleaned up
            assert receiverHby.db.kramTRQS.get(keys=partialKey) == []
            assert receiverHby.db.kramTSGS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSCS.get(keys=partialKey) == []
            assert receiverHby.db.kramSSTS.get(keys=partialKey) == []
            assert receiverHby.db.kramFRCS.get(keys=partialKey) == []
            assert receiverHby.db.kramTDCS.get(keys=partialKey) == []
            assert receiverHby.db.kramPTDS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSQS.get(keys=partialKey) == []
            assert receiverHby.db.kramBSSS.get(keys=partialKey) == []
            assert receiverHby.db.kramTMQS.get(keys=partialKey) == []


def test_pruning_exchanges(fakeHelpingClock):
    """
    Test pruning behavior for exchanges.

    Covers: pruning of exchanges with different timestamps, ensuring pruning is
    done for all messages belonging to the exchange.

    Steps:
    - create xip and seed it directly
    - accept an exn
    - accept an exn from the same sender with a later timestamp
    - Advance time to trigger pruning, since the exchange is outside the window,
      all messsages are deleted
    """

    # Instantiate Clock
    clock = fakeHelpingClock

    # Check the clock
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    # Setup sender/receiver
    salt_sender = Salter(raw=b'0123456789abcdef').qb64
    salt_receiver = Salter(raw=b'0123456789abcdeg').qb64

    with (openHby(name="sender", base="test", salt=salt_sender) as senderHby,
          openHby(name="receiver", base="test", salt=salt_receiver) as receiverHby):

        # Create single-key sender
        senderHab = senderHby.makeHab(name="sender", isith='1', icount=1, transferable=True)

        # Create receiver hab
        receiverHab = receiverHby.makeHab(name="receiver", isith='1', icount=1, transferable=True)

        # Load sender's ICP into receiver
        cross = Kevery(db=receiverHby.db, lax=False, local=False)

        senderIcp = senderHab.makeOwnEvent(sn=0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(senderIcp), kvy=cross)
        assert senderHab.pre in cross.kevers

        # Create Kramer with config
        with openCF(name="kram", base="test") as cf:
            cf.put(KRAM_INTEGRATION_CONFIG)
            kramer = Kramer(db=receiverHby.db, cf=cf)
            assert kramer.enabled

            # Create Kevery
            kvy = Kevery(db=receiverHby.db, lax=False, local=False, kramer=kramer)

            # Setup Doist with PruneDoer
            tock = 1
            limit = 1.0

            # Create PruneDoer
            pruneDoer = Pruner(kramer,tock)

            doist = doing.Doist(tock=tock, limit=limit)
            deeds = doist.enter(doers=[pruneDoer])

            stamp = helping.nowIso8601()
            prefixer = Prefixer(qb64=senderHab.pre)
            verfers = senderHab.kever.verfers

            # Test with seeded xip via kramit directly

            xip = exchept(sender=senderHab.pre,
                          receiver=receiverHab.pre,
                          route="/test/exchange",
                          stamp=stamp)

            # Sign xip
            sigers = senderHab.mgr.sign(ser=xip.raw,
                                        verfers=senderHab.kever.verfers,
                                        indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Call kramit directly (processMsg rejects xip)
            result = kramer.kramit(xip, **kwa)
            assert result is not None  # xip accepted

            # Assert: tmsc entry created, xip's exId is its own SAID
            cache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, xip.said))
            assert cache is not None
            assert cache.mdt == stamp
            assert cache.xdt == stamp  # xip's xdt == its own dt

            # Send first exn with exchange ID via processMsg
            firstStamp = helping.nowIso8601()
            assert firstStamp == "2021-01-01T00:00:00.000000+00:00"

            exn = exchange(sender=senderHab.pre,
                           receiver=receiverHab.pre,
                           xid=xip.said,
                           route="/test/exchange",
                           attributes=dict(n='5c'),
                           stamp=firstStamp)

            sigers = senderHab.mgr.sign(ser=exn.raw,
                                    verfers=senderHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Error raised due to lack of exchanger
            with pytest.raises(ValidationError):
                kvy.processMsg(exn, **kwa)

            # Assert tmsc entry created for exn
            firstCache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn.said))
            assert firstCache is not None
            assert firstCache.mdt == firstStamp
            assert firstCache.xdt == stamp  # inherited from xip's xdt
            assert firstCache.mdt == firstCache.xdt

            # Run pruner, shouldn't prune anything
            doist.recur(deeds=deeds)

            # cache is still here
            assert firstCache is not None

            # Send another message with a later stamp
            clock.advance(seconds=1)
            secondStamp = helping.nowIso8601() # 1s after xdt
            assert secondStamp == "2021-01-01T00:00:01.000000+00:00"

            exn2 = exchange(sender=senderHab.pre,
                            receiver=receiverHab.pre,
                            xid=xip.said,
                            route="/test/exchange",
                            attributes=dict(n='5c'),
                            stamp=secondStamp)

            sigers = senderHab.mgr.sign(ser=exn2.raw,
                                    verfers=senderHab.kever.verfers,
                                    indexed=True)
            kwa = dict(ssgs=[(prefixer, sigers)])

            # Error raised due to lack of exchanger
            with pytest.raises(ValidationError):
                kvy.processMsg(exn2, **kwa)

            # Assert tmsc entry created for exn2
            secondCache = receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn2.said))
            assert secondCache is not None
            assert secondCache.mdt == secondStamp
            assert secondCache.xdt == stamp  # inherited from xip's xdt
            assert secondCache.mdt != secondCache.xdt   # message time and exchange time are different

            # Delete or archive any cache entries (all messages associated with the exchange) where [xdt, xdt+xl] is not true.
            # Advance time to prune the exchange using pxl (pruning exchange lag)
            delta = (firstCache.pxl/1000)
            clock.advance(seconds=delta)
            assert helping.nowIso8601() == "2021-01-01T00:05:01.000000+00:00"

            doist.recur(deeds=deeds)

            # Xip and First Cache is pruned
            assert receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn.said)) is None
            assert receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, xip.said)) is None

            # Second Cache is also pruned because it belongs to the same exchange
            assert receiverHby.db.kramTMSC.get(keys=(senderHab.pre, xip.said, exn2.said)) is None
