# -*- encoding: utf-8 -*-
"""
tests.peer.test_exchanging module

"""
import json

import pysodium
import pytest

from keri import Kinds, Vrsn_1_0, Vrsn_2_0
from keri.kering import MissingSignatureError
from keri.core import (Salter, Counter, Dater, Texter, Kevery, Kramer,
                       Diger, Prefixer, Number,
                       SealSource, SerderKERI, Parser, messagize,
                       MtrDex, Codens, exchange)

from keri.app import (Notifier, Counselor, Multiplexor,
                      openCF, openHab, openHby,
                      multisigInceptExn, multisigRotateExn)
from keri.app.grouping import loadHandlers

from keri.peer import (Exchanger, nesting, serializeMessage, specialExchange,
                       verify)
from keri.vdr import incept

TEST_VERSION = Vrsn_1_0


def test_nesting():
    paths = ['a']
    val = "-JAbccDefg"
    pathed = dict()

    np = nesting(paths, pathed, val)
    assert np == pathed
    assert pathed == {'a': '-JAbccDefg'}

    paths = ['a', 'b']
    val = "-JAbccDefg"
    pathed = dict()

    np = nesting(paths, pathed, val)
    assert np == pathed
    assert pathed == {'a': {'b': '-JAbccDefg'}}

    paths = ['a', 'b', 'c', 'd', 'e']
    val = "-JAbccDefg"
    pathed = dict()

    np = nesting(paths, pathed, val)
    assert np == pathed
    assert pathed == {'a': {'b': {'c': {'d': {'e': '-JAbccDefg'}}}}}

    paths = []
    val = "-JAbccDefg"
    pathed = dict()

    np = nesting(paths, pathed, val)
    assert np == val
    assert pathed == {}


def test_essrs():
    kwa = dict(version=TEST_VERSION, kind=Kinds.json)
    with openHab(name="sid", base="test", salt=b'0123456789abcdef', **kwa) as (hby, hab), \
            openHab(name="rec", base="test", salt=b'0123456789abcdef', **kwa) as (recHby, recHab):

        ims = hab.msgOwnInception(framed=True, gvrsn=TEST_VERSION)
        Parser(version=TEST_VERSION).parse(ims=ims, kvy=recHby.kvy)
        # create the test message with essr attachment
        msg = dict(msg="This is a test message that must be secured", i=hab.pre)
        rkever = recHab.kever
        pubkey = pysodium.crypto_sign_pk_to_box_pk(rkever.verfers[0].raw)
        raw = pysodium.crypto_box_seal(json.dumps(msg).encode("utf-8"), pubkey)

        texter = Texter(raw=raw)
        diger = Diger(ser=raw, code=MtrDex.Blake3_256)
        essr, _ = specialExchange(sender=hab.pre,
                                  route='/essr/req',
                                  modifiers=dict(src=hab.pre,
                                                 dest=recHab.pre),
                                  diger=diger,
                                  **kwa)
        ims = hab.endorse(serder=essr, framed=True, gvrsn=TEST_VERSION)
        ims.extend(Counter(Codens.ESSRPayloadGroup, count=1,
                                version=TEST_VERSION).qb64b)
        ims.extend(texter.qb64b)

        exc = Exchanger(hby=recHby, handlers=[])
        Parser(version=TEST_VERSION).parse(ims=ims,
                               kvy=recHby.kvy,
                               exc=exc)

        # Pull the logged exn and verify the attributes digest matches the attachment
        serder = recHby.db.exns.get(keys=(essr.said,))
        assert serder.ked['a'] == diger.qb64

        # Pull the logged ESSR attachment and verify it is the one attached
        texter = recHby.db.essrs.get(keys=(serder.said,))
        raw = recHab.decrypt(ser=texter[0].raw)
        assert json.loads(raw.decode("utf-8")) == msg

        # Test with invalid diger
        diger = Diger(qb64="EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o")
        essr, _ = specialExchange(sender=hab.pre,
                                  route='/essr/req',
                                  modifiers=dict(src=hab.pre, dest=recHab.pre),
                                  diger=diger,
                                  **kwa)
        ims = hab.endorse(serder=essr, framed=True, gvrsn=TEST_VERSION)
        ims.extend(Counter(Codens.ESSRPayloadGroup, count=1,
                                version=TEST_VERSION).qb64b)
        ims.extend(texter[0].qb64b)

        Parser(version=TEST_VERSION).parse(ims=ims, kvy=recHby.kvy, exc=exc)
        assert recHby.db.exns.get(keys=(essr.said,)) is None


def test_hab_exchange(mockHelpingNowUTC):
    kwa = dict(version=TEST_VERSION, kind=Kinds.json)
    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64) as hby:
        hab = hby.makeHab(name="test", **kwa)
        assert hab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        nonce = "AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"
        regser = incept(hab.pre,
                        baks=[],
                        toad=0,
                        cnfg=[],
                        nonce=nonce,
                        code=MtrDex.Blake3_256,
                        **kwa)
        seal = dict(i=regser.pre, s=regser.sn, d=regser.said)
        msg = hab.interact(data=[seal], framed=True, gvrsn=TEST_VERSION, **kwa)

        embeds = dict(
            vcp=regser.raw,
            ixn=msg,
        )

        data = dict(m="Let's create a registry")
        msg = hab.exchange(route="/multisig/registry/incept",
                           attributes=data,
                           embeds=embeds,
                           framed=True,
                           gvrsn=TEST_VERSION,
                           **kwa)
        assert msg == (b'{"v":"KERI10JSON000399_","t":"exn","d":"EFKuL1JIrM6WMwjzL5YV'
                       b'mEycaAUGQJ7JYYx5Bjx7f70f","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIy'
                       b'ge6mBl2QV8dDjI3","rp":"","p":"","dt":"2021-01-01T00:00:00.00'
                       b'0000+00:00","r":"/multisig/registry/incept","q":{},"a":{"m":'
                       b'"Let\'s create a registry"},"e":{"vcp":{"v":"KERI10JSON00010f'
                       b'_","t":"vcp","d":"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfv'
                       b'VB","i":"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB","ii":'
                       b'"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"0","c":['
                       b'],"bt":"0","b":[],"n":"AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC'
                       b'3-l8_K-"},"ixn":{"v":"KERI10JSON000138_","t":"ixn","d":"EFuF'
                       b'nevyDFfpWG6il-6Qcv0ne0ZIItLwanCwI-SU8A9j","i":"EIaGMMWJFPmtX'
                       b'znY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"1","p":"EIaGMMWJFPmtXz'
                       b'nY1IIiKDIrg-vIyge6mBl2QV8dDjI3","a":[{"i":"EI6hBlgkWoJgkZyfL'
                       b'W35_UyM4nIK44OgsSwFR_WOfvVB","s":0,"d":"EI6hBlgkWoJgkZyfLW35'
                       b'_UyM4nIK44OgsSwFR_WOfvVB"}]},"d":"EL5Nkm6T7HG_0GW6uwqYSZwlH2'
                       b'3khtXvsVE-dq8eO_eE"}}-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl'
                       b'2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-v'
                       b'Iyge6mBl2QV8dDjI3-AABAAAB3Gc71DLRGTOLayjcb3G3ILgHKiG1SOij8J3'
                       b'ce2q5fL-RV1hLc4VhmEEe81tJRmi3Mois0N0sO-5j5RUTZFoO-LAa5AACAA-'
                       b'e-ixn-AABAADprTWp4llIzVzBM7VVsDOgXVJdoiVXutsWJEbDJ2pMdjXjNi1'
                       b'xKALBSZ1ZgRoUsD--LgUQkXIdjLoQ19XPvJMJ')

        exn = SerderKERI(raw=msg)

        hab2 = hby.makeHab(name="respondant", **kwa)
        regser = incept(hab2.pre,
                        baks=[],
                        toad=0,
                        cnfg=[],
                        nonce=nonce,
                        code=MtrDex.Blake3_256,
                        **kwa)

        seal = dict(i=regser.pre, s=regser.sn, d=regser.said)
        msg = hab2.interact(data=[seal], framed=True, gvrsn=TEST_VERSION, **kwa)

        embeds = dict(
            vcp=regser.raw,
            ixn=msg,
        )

        data = dict(m="Lets create this registry instead")
        msg = hab2.exchange(receiver="",
                            prior=exn.said,
                            route="/multisig/registry/incept",
                            attributes=data,
                            embeds=embeds,
                            framed=True,
                            gvrsn=TEST_VERSION,
                            **kwa)
        assert msg == (b'{"v":"KERI10JSON0003cf_","t":"exn","d":"EGSdBnzfHi8z6pG2yuEw'
                       b'quSuYgw53yEbyucL70aDH1mL","i":"EIREQlatUJODbKogZfa3IqXZ90XdZ'
                       b'A0qJMVliI61Bcc2","rp":"","p":"EFKuL1JIrM6WMwjzL5YVmEycaAUGQJ'
                       b'7JYYx5Bjx7f70f","dt":"2021-01-01T00:00:00.000000+00:00","r":'
                       b'"/multisig/registry/incept","q":{},"a":{"m":"Lets create thi'
                       b's registry instead"},"e":{"vcp":{"v":"KERI10JSON00010f_","t"'
                       b':"vcp","d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","i'
                       b'":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","ii":"EIREQ'
                       b'latUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","s":"0","c":[],"bt"'
                       b':"0","b":[],"n":"AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K'
                       b'-"},"ixn":{"v":"KERI10JSON000138_","t":"ixn","d":"EOek9JVKNe'
                       b'uW-5UNeHYCTDe70_GtvRwP672oWMNBJpA5","i":"EIREQlatUJODbKogZfa'
                       b'3IqXZ90XdZA0qJMVliI61Bcc2","s":"1","p":"EIREQlatUJODbKogZfa3'
                       b'IqXZ90XdZA0qJMVliI61Bcc2","a":[{"i":"EB5mts6qrWOZrxjma6lSTjA'
                       b'dPZ0NSHM1HC3IndbS_giB","s":0,"d":"EB5mts6qrWOZrxjma6lSTjAdPZ'
                       b'0NSHM1HC3IndbS_giB"}]},"d":"EM3gLTzQ9GmKd50Rlm_kiIkeYkxb004e'
                       b'oOsWahz70TqJ"}}-FABEIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61B'
                       b'cc20AAAAAAAAAAAAAAAAAAAAAAAEIREQlatUJODbKogZfa3IqXZ90XdZA0qJ'
                       b'MVliI61Bcc2-AABAAByi9jCGR7BZs5iB0K8eyCbrhPZIwTQISa2Hy2uE9ws5'
                       b'YKZfIGgmG9zElwaWgbaH9muZe4N8KahQY7T8KVvAnIN-LAa5AACAA-e-ixn-'
                       b'AABAACaoxfQp5L_Gd0nKqJXMbLTXzkrJJDd8RFxWdTSesAMydUzmJQlGt0T9'
                       b'h8L7SwIrq8yBinj990PLJHl7sXmq04I')

        # Test exn from non-transferable AID
        hab = hby.makeHab(name="test1", transferable=False, **kwa)
        assert hab.pre == "BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG"

        embeds = dict(
            vcp=hab.endorse(regser, framed=True, gvrsn=TEST_VERSION)
        )
        msg = hab.exchange(route="/multisig/registry/incept", attributes=data,
                           embeds=embeds, receiver="", framed=True, gvrsn=TEST_VERSION, **kwa)
        assert msg == (b'{"v":"KERI10JSON000264_","t":"exn","d":"EHpPvOzki6YEh7vtcTQUx3rI'
                    b'CVCGyrE9WxYAaJIvDJDU","i":"BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFV'
                    b'lCeiZPG","rp":"","p":"","dt":"2021-01-01T00:00:00.000000+00:00",'
                    b'"r":"/multisig/registry/incept","q":{},"a":{"m":"Lets create thi'
                    b's registry instead"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vc'
                    b'p","d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","i":"EB5mt'
                    b's6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","ii":"EIREQlatUJODbKogZ'
                    b'fa3IqXZ90XdZA0qJMVliI61Bcc2","s":"0","c":[],"bt":"0","b":[],"n":'
                    b'"AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"d":"ENC6w8wUj-G'
                    b'p_RpAJN5q4Lf00IHstzNLUvkh3ZvgHGP_"}}-CABBJZ_LF61JTCCSCIw2Q4ozE2M'
                    b'sbRC4m-N6-tFVlCeiZPG0BAcmtiiDc82NMYkbVb70WBkekCt8YUEXEaWKeSOMRKb'
                    b'dTcWbEvopiman-9jhv9ck2NgZhmy25zgpCSIliWgUnwO-LAl5AACAA-e-vcp-CAB'
                    b'BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG0BDjOC4j0Co6P0giMylR'
                    b'47149eJ8Yf_hO-32_TpY77KMVCWCf0U8GuZPIN76R2zsyT_eARvS_zQsX1ebjl3P'
                    b'MP0D')


def test_serialize_message_round_trips_stored_nested_substreams(mockHelpingNowUTC):
    with openHab(name="nested-save-src", base="test", salt=b'0123456789abcdef', version=Vrsn_2_0, kind=Kinds.json) as (_, hab), \
            openHab(name="nested-save-rec", base="test", salt=b'abcdef0123456789', version=Vrsn_2_0, kind=Kinds.json) as (recHby, _):

        # Build a V2 multisig wrapper around one child inception event
        aids = [hab.pre, "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"]

        # Seed the receiver with the sender's member AID so the exchange can be accepted
        Parser(version=Vrsn_2_0).parse(ims=bytearray(hab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)),
                                       kvy=recHby.kvy,
                                       local=True)

        # The child event carried by the exchange is a framed V2 inception stream
        icp = hab.msgOwnEvent(sn=hab.kever.sn, framed=True, gvrsn=Vrsn_2_0)
        inner = SerderKERI(raw=icp)

        # Wrap that child in a V2 /multisig/icp EXN with one nested substream
        exn, atc = multisigInceptExn(hab=hab, smids=aids, rmids=aids, icp=icp,
                                     version=Vrsn_2_0, kind=Kinds.json)

        # Process the exchange through the exchanger so nested children are persisted
        exc = Exchanger(hby=recHby, handlers=[])
        Parser(version=Vrsn_2_0).parse(ims=bytearray(exn.raw + atc),
                                       kvy=recHby.kvy,
                                       exc=exc)

        # The exchanger should have stored exactly one nested child for this EXN
        stored = recHby.db.enst.get(keys=(exn.said,))
        assert len(stored) == 1

        # Re-serialize the saved EXN from durable storage rather than the original wire bytes
        # This is the regression target: saved V2 proposals used to lose their nested child here
        msg = serializeMessage(recHby, exn.said, framed=True)

        # Parse the rebuilt message as a normal V2 stream and confirm the child substream survived
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(msg),
                                                framed=True,
                                                processive=False)

        # Rebuilt storage should produce exactly one outer EXN
        assert len(parsed) == 1

        # That rebuilt EXN should still contain exactly one nested child stream
        assert len(parsed[0].nests) == 1

        # The child inside the rebuilt message should be the same child that was originally sent
        assert parsed[0].nests[0].serder.said == inner.said


def test_source_seal_couple_round_trips_as_resolved_triple(mockHelpingNowUTC):
    """Durable replay makes the implicit sender of a seal couple explicit."""
    kwa = dict(version=Vrsn_2_0, kind=Kinds.json)
    with openHab(name="seal-source", base="test",
                 salt=b'0123456789abcdef', **kwa) as (_, sender), \
            openHab(name="seal-receiver", base="test",
                    salt=b'abcdef0123456789', **kwa) as (receiverHby, _):
        Parser(version=Vrsn_2_0).parse(
            ims=bytearray(sender.msgOwnEvent(sn=0,
                                             framed=True,
                                             gvrsn=Vrsn_2_0)),
            kvy=receiverHby.kvy,
            local=True,
        )
        exn = exchange(sender=sender.pre,
                       route="/test/seal-source",
                       attributes=dict(m="sealed exchange"),
                       **kwa)
        anchor = sender.interact(data=[dict(d=exn.said)],
                                 framed=True,
                                 gvrsn=Vrsn_2_0,
                                 **kwa)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(anchor),
                                       kvy=receiverHby.kvy,
                                       local=True)

        number = Number(sn=sender.kever.sn)
        diger = Diger(qb64=sender.kever.serder.said)
        assert receiverHby.db.kels.getLast(
            keys=sender.kever.prefixer.qb64b, on=number.sn) == diger.qb64
        anchorSerder = receiverHby.db.evts.get(
            keys=(sender.kever.prefixer.qb64b, diger.qb64b))
        assert anchorSerder is not None
        assert anchorSerder.seals == [dict(d=exn.said)]
        msg = messagize(exn,
                        bonds=[SealSource(s=number, d=diger)],
                        framed=True,
                        gvrsn=Vrsn_2_0)
        exchanger = Exchanger(hby=receiverHby, handlers=[])
        receiverHby.kvy.kramer = None
        Parser(version=Vrsn_2_0).parse(ims=bytearray(msg),
                                       framed=True,
                                       kvy=receiverHby.kvy,
                                       exc=exchanger)

        assert [(snumber.sn, sdiger.qb64)
                for snumber, sdiger in receiverHby.db.ests.get(
                    keys=(exn.said, sender.pre))] == [
            (number.sn, diger.qb64),
        ]
        assert receiverHby.db.exns.get(keys=(exn.said,)) is not None

        replay = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(serializeMessage(receiverHby, exn.said,
                                           framed=True)),
            framed=True,
            processive=False,
        )[0]
        assert replay.sscs == []
        assert [(prefixer.qb64, snumber.sn, sdiger.qb64)
                for prefixer, snumber, sdiger in replay.ssts] == [
            (sender.pre, number.sn, diger.qb64),
        ]

        signed = exchange(sender=sender.pre,
                          route="/test/seal-source",
                          attributes=dict(m="signed and sealed exchange"),
                          **kwa)
        anchor = sender.interact(data=[dict(d=signed.said)],
                                 framed=True,
                                 gvrsn=Vrsn_2_0,
                                 **kwa)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(anchor),
                                       kvy=receiverHby.kvy,
                                       local=True)
        sourceSeal = (sender.kever.prefixer,
                      Number(sn=sender.kever.sn),
                      Diger(qb64=sender.kever.serder.said))
        senderSigs = sender.sign(ser=signed.raw, indexed=True)
        msg = messagize(
            signed,
            lsgs=[(sender.kever.prefixer, senderSigs)],
            bonds=[SealSource(s=sourceSeal[1], d=sourceSeal[2])],
            framed=True,
            gvrsn=Vrsn_2_0,
        )
        config = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000,
                          5000, 60000, 300000],
                },
            },
        }
        with openCF(name="signed-seal-kram", base="test", temp=True) as cf:
            cf.put(config)
            kvy = Kevery(db=receiverHby.db,
                         lax=False,
                         local=False,
                         kramer=Kramer(db=receiverHby.db, cf=cf),
                         exc=exchanger)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(msg), kvy=kvy)

        assert len(list(receiverHby.db.esigs.getTopItemIter(
            keys=(signed.said, sender.pre, "")))) == 1
        assert [(snumber.sn, sdiger.qb64)
                for snumber, sdiger in receiverHby.db.ests.get(
                    keys=(signed.said, sender.pre))] == [
            (sourceSeal[1].sn, sourceSeal[2].qb64),
        ]
        verify(receiverHby, signed)

        replay = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(serializeMessage(receiverHby, signed.said,
                                           framed=True)),
            framed=True,
            processive=False,
        )[0]
        assert [(prefixer.qb64, snumber.sn, sdiger.qb64, len(sigers))
                for prefixer, snumber, sdiger, sigers in replay.tsgs] == [
            (sender.pre, sender.kever.lastEst.s,
             sender.kever.lastEst.d, len(senderSigs)),
        ]
        assert [(prefixer.qb64, snumber.sn, sdiger.qb64)
                for prefixer, snumber, sdiger in replay.ssts] == [
            (sender.pre, sourceSeal[1].sn, sourceSeal[2].qb64),
        ]


def test_non_ipex_rejects_non_sender_evidence(mockHelpingNowUTC):
    """Non-IPEX routes keep the existing sender-only evidence contract."""
    kwa = dict(version=Vrsn_2_0, kind=Kinds.json)
    with openHab(name="extra-sender", base="test",
                 salt=b'0123456789abcdef', **kwa) as (_, sender), \
            openHab(name="extra-endorser", base="test",
                    salt=b'abcdef0123456789', **kwa) as (_, endorser), \
            openHab(name="extra-unknown", base="test",
                    salt=b'0123456789abcdeg', **kwa) as (_, unknown), \
            openHab(name="extra-receiver", base="test",
                    salt=b'fedcba9876543210', **kwa) as (receiverHby, _):
        for hab in (sender, endorser):
            msg = hab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(msg),
                                           kvy=receiverHby.kvy,
                                           local=True)

        def group(hab, ser):
            return (hab.kever.prefixer,
                    Number(sn=hab.kever.lastEst.s),
                    Diger(qb64=hab.kever.lastEst.d),
                    hab.sign(ser=ser, indexed=True))

        exchanger = Exchanger(hby=receiverHby, handlers=[])
        ordinary = exchange(sender=sender.pre,
                            route="/test/ordinary",
                            attributes=dict(m="ordinary"),
                            **kwa)
        exchanger.processEvent(ordinary,
                               tsgs=[group(sender, ordinary.raw)])
        assert receiverHby.db.exns.get(keys=(ordinary.said,)).said == ordinary.said

        transferableCigar = exchange(
            sender=sender.pre,
            route="/test/ordinary",
            attributes=dict(m="transferable cigar"),
            **kwa,
        )
        senderCigars = sender.sign(ser=transferableCigar.raw, indexed=False)
        assert senderCigars[0].verfer.transferable
        with pytest.raises(MissingSignatureError):
            exchanger.processEvent(transferableCigar, cigars=senderCigars)
        assert receiverHby.db.exns.get(keys=(transferableCigar.said,)) is None

        mixed = exchange(sender=sender.pre,
                         route="/test/ordinary",
                         attributes=dict(m="mixed sender evidence"),
                         **kwa)
        ignoredCigars = endorser.sign(ser=b"different exchange message",
                                      indexed=False)
        exchanger.processEvent(mixed,
                               tsgs=[group(sender, mixed.raw)],
                               cigars=ignoredCigars)
        assert receiverHby.db.exns.get(keys=(mixed.said,)).said == mixed.said
        assert receiverHby.db.ecigs.get(keys=(mixed.said,)) == []

        mixedSeal = exchange(sender=sender.pre,
                             route="/test/ordinary",
                             attributes=dict(m="mixed source seal"),
                             **kwa)
        foreignSeal = (endorser.kever.prefixer,
                       Number(sn=endorser.kever.sn),
                       Diger(qb64=endorser.kever.serder.said))
        exchanger.processEvent(mixedSeal,
                               tsgs=[group(sender, mixedSeal.raw)],
                               ssts=[foreignSeal])
        assert receiverHby.db.exns.get(
            keys=(mixedSeal.said,)).said == mixedSeal.said
        assert receiverHby.db.ests.get(
            keys=(mixedSeal.said, endorser.pre)) == []

        signedWithMissingSeal = exchange(
            sender=sender.pre,
            route="/test/ordinary",
            attributes=dict(m="authenticated with missing sender seal"),
            **kwa,
        )
        missingSenderSeal = (sender.kever.prefixer,
                             Number(sn=sender.kever.sn + 1),
                             Diger(qb64=sender.kever.serder.said))
        queryCueCount = sum(cue.get("kin") == "query"
                            for cue in exchanger.cues)
        exchanger.processEvent(
            signedWithMissingSeal,
            tsgs=[group(sender, signedWithMissingSeal.raw)],
            ssts=[missingSenderSeal],
        )
        assert receiverHby.db.exns.get(
            keys=(signedWithMissingSeal.said,)).said == signedWithMissingSeal.said
        assert sum(cue.get("kin") == "query"
                   for cue in exchanger.cues) == queryCueCount
        assert receiverHby.db.ests.get(
            keys=(signedWithMissingSeal.said, sender.pre)) == []

        withExtra = exchange(sender=sender.pre,
                             route="/test/ordinary",
                             attributes=dict(m="foreign evidence"),
                             **kwa)
        with pytest.raises(MissingSignatureError):
            exchanger.processEvent(
                withExtra,
                tsgs=[group(sender, withExtra.raw),
                      group(endorser, withExtra.raw)],
            )

        assert receiverHby.db.exns.get(keys=(withExtra.said,)) is None
        assert list(receiverHby.db.esigs.getTopItemIter(
            keys=(withExtra.said, endorser.pre, "")
        )) == []

        missingSender = exchange(sender=unknown.pre,
                                 route="/test/ordinary",
                                 attributes=dict(m="missing sender state"),
                                 **kwa)
        with pytest.raises(MissingSignatureError):
            exchanger.processEvent(
                missingSender,
                tsgs=[group(unknown, missingSender.raw),
                      group(endorser, missingSender.raw)],
            )
        assert any(cue.get("kin") == "query" and
                   cue["q"]["pre"] == unknown.pre
                   for cue in exchanger.cues)

        unknownIcp = unknown.msgOwnEvent(sn=0, framed=True,
                                         gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(unknownIcp),
                                       kvy=receiverHby.kvy,
                                       local=True)
        exchanger.processEscrow()
        assert receiverHby.db.exns.get(keys=(missingSender.said,)) is None

        unsupportedOnly = exchange(sender=sender.pre,
                                   route="/test/ordinary",
                                   attributes=dict(m="foreign only input"),
                                   **kwa)
        with pytest.raises(MissingSignatureError):
            exchanger.processEvent(
                unsupportedOnly,
                tsgs=[group(endorser, unsupportedOnly.raw)],
            )
        assert receiverHby.db.epse.get(
            keys=(unsupportedOnly.said,)) is None

        foreignOnly = exchange(sender=sender.pre,
                               route="/test/ordinary",
                               attributes=dict(m="foreign only"),
                               **kwa)
        exchanger.logEvent(foreignOnly,
                           tsgs=[group(endorser, foreignOnly.raw)])
        with pytest.raises(MissingSignatureError):
            verify(receiverHby, foreignOnly)


def test_escrow_replay_persists_only_verified_evidence(mockHelpingNowUTC):
    """Exchanger escrow rows do not bypass evidence selection on replay."""
    kwa = dict(version=Vrsn_2_0, kind=Kinds.json)

    class EvidenceHandler:
        resource = "/test/evidence"

        @staticmethod
        def verify(serder, **kwa):
            return True

        @staticmethod
        def verifyEvidence(serder, *, tsgs=None, cigars=None, sourceSeals=None,
                           invalid=False):
            return tsgs or [], cigars or [], sourceSeals or []

        @staticmethod
        def handle(serder, **kwa):
            return None

    with openHab(name="escrow-sender", base="test",
                 salt=b'0123456789abcdef', **kwa) as (_, sender), \
            openHab(name="escrow-endorser", base="test",
                    salt=b'abcdef0123456789', **kwa) as (_, endorser), \
            openHab(name="escrow-cigar", base="test",
                    salt=b'0123456789abcdeg', transferable=False,
                    **kwa) as (_, cigarEndorser), \
            openHab(name="escrow-receiver", base="test",
                    salt=b'fedcba9876543210', **kwa) as (receiverHby, receiver):
        endorserIcp = endorser.msgOwnEvent(sn=0, framed=True,
                                           gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(endorserIcp),
                                       kvy=receiverHby.kvy,
                                       local=True)

        exchanger = Exchanger(hby=receiverHby,
                              handlers=[EvidenceHandler()])
        exn = exchange(sender=sender.pre,
                       route=EvidenceHandler.resource,
                       attributes=dict(m="escrow evidence"),
                       **kwa)

        def group(hab, sigers):
            return (hab.kever.prefixer,
                    Number(sn=hab.kever.lastEst.s),
                    Diger(qb64=hab.kever.lastEst.d),
                    sigers)

        senderGroup = group(sender, sender.sign(ser=exn.raw, indexed=True))
        endorserGroup = group(
            endorser,
            endorser.sign(ser=exn.raw, indexed=True),
        )
        invalidGroup = group(
            receiver,
            receiver.sign(ser=b"different exchange message", indexed=True),
        )
        validCigar = cigarEndorser.sign(ser=exn.raw, indexed=False)
        invalidCigar = cigarEndorser.sign(
            ser=b"different exchange message", indexed=False)

        endorserAnchor = endorser.interact(
            data=[dict(d=exn.said)],
            framed=True,
            version=Vrsn_2_0,
            gvrsn=Vrsn_2_0,
        )
        Parser(version=Vrsn_2_0).parse(ims=bytearray(endorserAnchor),
                                       kvy=receiverHby.kvy,
                                       local=True)
        validSeal = (endorser.kever.prefixer,
                     Number(sn=endorser.kever.sn),
                     Diger(qb64=endorser.kever.serder.said))
        invalidSeal = (receiver.kever.prefixer,
                       Number(sn=receiver.kever.sn),
                       Diger(qb64=receiver.kever.serder.said))

        with pytest.raises(MissingSignatureError):
            exchanger.processEvent(exn,
                                   tsgs=[senderGroup, endorserGroup,
                                         invalidGroup],
                                   cigars=validCigar + invalidCigar,
                                   ssts=[validSeal, invalidSeal])

        assert receiverHby.db.epse.get(keys=(exn.said,)) is not None
        assert len(list(receiverHby.db.esigs.getTopItemIter(
            keys=(exn.said, endorser.pre, "")))) == 1
        assert len(receiverHby.db.ecigs.get(keys=(exn.said,))) == 2

        senderIcp = sender.msgOwnEvent(sn=0, framed=True,
                                       gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(senderIcp),
                                       kvy=receiverHby.kvy,
                                       local=True)
        exchanger.processEscrow()

        assert receiverHby.db.exns.get(keys=(exn.said,)) is not None
        assert len(list(receiverHby.db.esigs.getTopItemIter(
            keys=(exn.said, sender.pre, "")))) == 1
        assert len(list(receiverHby.db.esigs.getTopItemIter(
            keys=(exn.said, endorser.pre, "")))) == 1
        assert list(receiverHby.db.esigs.getTopItemIter(
            keys=(exn.said, receiver.pre, ""))) == []

        sourceSeals = receiverHby.db.ests.get(
            keys=(exn.said, endorser.pre))
        assert [(number.sn, diger.qb64)
                for number, diger in sourceSeals] == [
            (endorser.kever.sn, endorser.kever.serder.said),
        ]
        assert receiverHby.db.ests.get(
            keys=(exn.said, receiver.pre)) == []
        assert [(verfer.qb64, cigar.qb64)
                for verfer, cigar in receiverHby.db.ecigs.get(
                    keys=(exn.said,))] == [
            (cigarEndorser.pre, validCigar[0].qb64),
        ]

        serialized = serializeMessage(receiverHby, exn.said, framed=True)
        assert serialized is not None
        parsed = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(serialized), framed=True, processive=False)
        replayGroups = {prefixer.qb64: (number, diger, sigers)
                        for prefixer, number, diger, sigers
                        in parsed[0].tsgs}
        number, diger, sigers = replayGroups[endorser.pre]
        assert (number.sn, diger.qb64, len(sigers)) == (
            endorser.kever.lastEst.s,
            endorser.kever.lastEst.d,
            1,
        )
        assert [(prefixer.qb64, number.sn, diger.qb64)
                for prefixer, number, diger in parsed[0].ssts] == [
            (endorser.pre, endorser.kever.sn, endorser.kever.serder.said),
        ]
        assert [(cigar.verfer.qb64, cigar.qb64)
                for cigar in parsed[0].cigars] == [
            (cigarEndorser.pre, validCigar[0].qb64),
        ]

        historical = exchange(sender=sender.pre,
                              route=EvidenceHandler.resource,
                              attributes=dict(m="historical endorsement"),
                              **kwa)
        historicalEst = endorser.kever.lastEst
        historicalSigs = endorser.sign(ser=historical.raw, indexed=True)
        endorserRot = endorser.rotate(framed=True,
                                     gvrsn=Vrsn_2_0,
                                     **kwa)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(endorserRot),
                                       kvy=receiverHby.kvy,
                                       local=True)
        exchanger.processEvent(
            historical,
            tsgs=[group(sender, sender.sign(ser=historical.raw,
                                            indexed=True)),
                  (endorser.kever.prefixer,
                   Number(sn=historicalEst.s),
                   Diger(qb64=historicalEst.d),
                   historicalSigs)],
        )
        assert receiverHby.db.exns.get(keys=(historical.said,)) is not None
        historicalRows = list(receiverHby.db.esigs.getTopItemIter(
            keys=(historical.said, endorser.pre, "")))
        assert len(historicalRows) == 1
        assert historicalRows[0][0][2:] == (
            f"{historicalEst.s:032x}",
            historicalEst.d,
        )
        historicalReplay = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(serializeMessage(receiverHby,
                                           historical.said,
                                           framed=True)),
            framed=True,
            processive=False,
        )[0]
        historicalGroups = {
            prefixer.qb64: (number, diger, sigers)
            for prefixer, number, diger, sigers in historicalReplay.tsgs
        }
        number, diger, sigers = historicalGroups[endorser.pre]
        assert (number.sn, diger.qb64, len(sigers)) == (
            historicalEst.s,
            historicalEst.d,
            1,
        )

        fallback = exchange(sender=sender.pre,
                            route=EvidenceHandler.resource,
                            attributes=dict(m="signature fallback"),
                            **kwa)
        fallbackSigs = endorser.sign(ser=fallback.raw, indexed=True)
        exchanger.processEvent(
            fallback,
            tsgs=[group(sender, sender.sign(ser=fallback.raw,
                                            indexed=True))],
            lsgs=[(endorser.kever.prefixer, fallbackSigs)],
            ssts=[validSeal],
        )
        fallbackRows = list(receiverHby.db.esigs.getTopItemIter(
            keys=(fallback.said, endorser.pre, "")))
        assert len(fallbackRows) == 1
        assert fallbackRows[0][0][2:] == (
            f"{endorser.kever.lastEst.s:032x}",
            endorser.kever.lastEst.d,
        )
        assert receiverHby.db.ests.get(
            keys=(fallback.said, endorser.pre)) == []


def test_complete_redelivery_replaces_temporary_evidence(mockHelpingNowUTC):
    """A complete redelivery cannot promote evidence from an older PSE row."""
    kwa = dict(version=Vrsn_2_0, kind=Kinds.json)

    class EvidenceHandler:
        resource = "/test/redelivery-evidence"

        @staticmethod
        def verify(serder, **kwa):
            return True

        @staticmethod
        def verifyEvidence(serder, *, tsgs=None, cigars=None, sourceSeals=None,
                           invalid=False):
            return tsgs or [], cigars or [], sourceSeals or []

        @staticmethod
        def handle(serder, **kwa):
            return None

    with openHab(name="redelivery-sender", base="test",
                 salt=b'0123456789abcdef', **kwa) as (_, sender), \
            openHab(name="redelivery-endorser", base="test",
                    salt=b'abcdef0123456789', **kwa) as (_, endorser), \
            openHab(name="redelivery-cigar", base="test",
                    salt=b'0123456789abcdeg', transferable=False,
                    **kwa) as (_, cigarEndorser), \
            openHab(name="redelivery-receiver", base="test",
                    salt=b'fedcba9876543210', **kwa) as (receiverHby, _):
        Parser(version=Vrsn_2_0).parse(
            ims=bytearray(endorser.msgOwnEvent(
                sn=0, framed=True, gvrsn=Vrsn_2_0)),
            kvy=receiverHby.kvy,
            local=True,
        )

        exchanger = Exchanger(hby=receiverHby,
                              handlers=[EvidenceHandler()])
        exn = exchange(sender=sender.pre,
                       route=EvidenceHandler.resource,
                       attributes=dict(m="complete redelivery"),
                       **kwa)

        def group(hab):
            return (hab.kever.prefixer,
                    Number(sn=hab.kever.lastEst.s),
                    Diger(qb64=hab.kever.lastEst.d),
                    hab.sign(ser=exn.raw, indexed=True))

        senderGroup = group(sender)
        endorserGroup = group(endorser)
        foreignCigars = cigarEndorser.sign(ser=exn.raw, indexed=False)
        endorserAnchor = endorser.interact(
            data=[dict(d=exn.said)], framed=True, gvrsn=Vrsn_2_0, **kwa)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(endorserAnchor),
                                       kvy=receiverHby.kvy,
                                       local=True)
        foreignSeal = (endorser.kever.prefixer,
                       Number(sn=endorser.kever.sn),
                       Diger(qb64=endorser.kever.serder.said))

        with pytest.raises(MissingSignatureError):
            exchanger.processEvent(exn,
                                   tsgs=[senderGroup, endorserGroup],
                                   cigars=foreignCigars,
                                   ssts=[foreignSeal])

        assert receiverHby.db.epse.get(keys=(exn.said,)) is not None
        assert len(list(receiverHby.db.esigs.getTopItemIter(
            keys=(exn.said, endorser.pre, "")))) == 1
        assert len(receiverHby.db.ecigs.get(keys=(exn.said,))) == 1
        assert len(receiverHby.db.ests.get(
            keys=(exn.said, endorser.pre))) == 1

        Parser(version=Vrsn_2_0).parse(
            ims=bytearray(sender.msgOwnEvent(
                sn=0, framed=True, gvrsn=Vrsn_2_0)),
            kvy=receiverHby.kvy,
            local=True,
        )
        exchanger.processEvent(exn, tsgs=[senderGroup])

        assert receiverHby.db.exns.get(keys=(exn.said,)) is not None
        assert receiverHby.db.epse.get(keys=(exn.said,)) is None
        assert len(list(receiverHby.db.esigs.getTopItemIter(
            keys=(exn.said, sender.pre, "")))) == 1
        assert list(receiverHby.db.esigs.getTopItemIter(
            keys=(exn.said, endorser.pre, ""))) == []
        assert receiverHby.db.ecigs.get(keys=(exn.said,)) == []
        assert receiverHby.db.ests.get(
            keys=(exn.said, endorser.pre)) == []
        verify(receiverHby, exn)

        before = serializeMessage(receiverHby, exn.said, framed=True)
        receiverHby.db.epse.put(keys=(exn.said,), val=exn)
        receiverHby.db.epsd.put(
            keys=(exn.said,),
            val=Dater(dts="2021-01-01T00:00:00.000000+00:00"),
        )
        exchanger.processEscrow()
        assert receiverHby.db.epse.get(keys=(exn.said,)) is None
        assert serializeMessage(receiverHby, exn.said, framed=True) == before


def test_v2_multisig_incept_escrow_replay_then_rotation_anchors_in_kel(mockHelpingNowUTC):

    # `hby1/hab1` is the local side under test; `hby2/hab2` acts as the remote signer.
    with openHab(name="lifecycle-local", base="test", salt=b'0123456789abcdef', version=Vrsn_2_0, kind=Kinds.json) as (hby1, hab1), \
            openHab(name="lifecycle-remote", base="test", salt=b'abcdef0123456789', version=Vrsn_2_0, kind=Kinds.json) as (hby2, hab2):

        # First exchange the member AID inception events so each side knows the other signer
        for src, dest in ((hab2, hby1), (hab1, hby2)):
            # Each participant ingests the other's inception into its local KEL
            Parser(version=Vrsn_2_0).parse(
                ims=bytearray(src.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)),
                kvy=dest.kvy,
                local=True,
            )

        # Build the same 2-of-2 group hab independently on both participants
        smids = [hab1.pre, hab2.pre]
        inits = dict(toad=0, wits=[], isith="2", nsith="2", version=Vrsn_2_0, kind=Kinds.json)

        # Each participant computes the same group habitat locally from the same member set
        ghab1 = hby1.makeGroupHab(group="lifecycle-group", mhab=hab1,
                                  smids=smids, rmids=None, **inits)
        ghab2 = hby2.makeGroupHab(group="lifecycle-group", mhab=hab2,
                                  smids=smids, rmids=None, **inits)

        # Set up notifier, counselor, mux, exchanger and load multisig handlers
        notifier = Notifier(hby=hby1)
        counselor = Counselor(hby=hby1, version=Vrsn_2_0, kind=Kinds.json)
        mux = Multiplexor(hby=hby1, notifier=notifier)
        exc = Exchanger(hby=hby1, handlers=[])
        loadHandlers(exc=exc, mux=mux)

        # Create the local participant's partially signed group inception event
        icp = ghab1.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=Vrsn_2_0)
        icpSerder = SerderKERI(raw=icp)

        # Wrap that local child in a V2 /multisig/icp EXN
        localExn, localAtc = multisigInceptExn(hab=ghab1.mhab, smids=ghab1.smids,
                                               rmids=ghab1.rmids, icp=icp,
                                               version=Vrsn_2_0, kind=Kinds.json)

        # Parse the local EXN without processing it so we can seed the mux with the local approval
        local = Parser(version=Vrsn_2_0).parse(ims=bytearray(localExn.raw + localAtc),
                                               framed=True,
                                               processive=False)[0]
        mux.add(local.serder, nests=local.nests)

        # Track the inner group inception in the counselor's multisig lifecycle
        prefixer = Prefixer(qb64=ghab1.pre)
        inceptNumber = Number(sn=0)
        inceptDiger = Diger(qb64=icpSerder.said)
        counselor.start(ghab=ghab1, prefixer=prefixer, number=inceptNumber, diger=inceptDiger)

        # Rotate the remote member AID before it sends its matching EXN
        # forcing the outer /multisig/icp exchange into exchanger escrow
        memberRot = hab2.rotate(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)

        # The remote participant independently builds the same partially signed group inception
        remoteIcp = ghab2.msgOwnInception(allowPartiallySigned=True, framed=True, gvrsn=Vrsn_2_0)
        remoteIcpSerder = SerderKERI(raw=remoteIcp)

        # Both participants should be proposing the same child inception SAID
        assert remoteIcpSerder.said == icpSerder.said

        # Wrap the remote copy in a V2 nested /multisig/icp EXN and send it to the local side
        remoteExn, remoteAtc = multisigInceptExn(hab=ghab2.mhab, smids=ghab2.smids,
                                                 rmids=ghab2.rmids, icp=remoteIcp,
                                                 version=Vrsn_2_0, kind=Kinds.json)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(remoteExn.raw + remoteAtc),
                                       exc=exc,
                                       local=False)

        # The EXN should now be escrowed, with its nested child preserved in the new db
        assert len(list(hby1.db.epse.getTopItemIter())) == 1

        # The escrowed EXN did not lose its nested child
        assert len(hby1.db.enst.get(keys=(remoteExn.said,))) == 1

        # The inner group inception cannot be in the group KEL yet because replay has not happened
        assert hby1.db.kels.getLast(keys=ghab1.pre, on=0) is None

        # Teach the local side about the remote member's latest key state, then retry the EXN escrow
        Parser(version=Vrsn_2_0).parse(ims=bytearray(memberRot), kvy=hby1.kvy, local=True)

        # The exchanger reloads the parked EXN plus the stored nested child from `enst`.
        exc.processEscrow()

        # Process any resulting group-event escrows so the inner inception can complete locally
        mux.kvy.processEscrows()

        # The replayed nested child should now merge the second signature onto the group inception
        sigers = hby1.db.sigs.get(keys=(icpSerder.preb, icpSerder.saidb))
        assert [siger.index for siger in sigers] == [0, 1]

        # With both signatures present, the inner group inception should be accepted into the group KEL
        assert hby1.db.kels.getLast(keys=ghab1.pre, on=0) == icpSerder.said

        # Let the counselor observe that the inception finished and mark the multisig operation complete
        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, number=inceptNumber, diger=inceptDiger)

        # Verify the saved remote EXN can still be re-serialized with its nested child intact after replay
        saved = serializeMessage(hby1, remoteExn.said, framed=True)

        # Parse the serialized-from-DB bytes, not the original remote wire bytes
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(saved),
                                                framed=True,
                                                processive=False)

        # Storage serialization should rebuild one outer EXN
        assert len(parsed) == 1

        # The stored outer EXN should still include its nested child
        assert len(parsed[0].nests) == 1

        # The nested child should still be the group inception event that just completed
        assert parsed[0].nests[0].serder.said == icpSerder.said

        # Rotate the local member AID and share that updated member state with the remote side first
        # This keeps the later /multisig/rot exchange focused on the group-rotation path, not exchange escrow
        memberRotLocal = hab1.rotate(framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(memberRotLocal), kvy=hby2.kvy, local=True)

        # Create the next partially signed group rotation locally using the current member keys
        # Use each member's current public key as the rotation signing key set
        merfers = [hab1.kever.verfers[0], hab2.kever.verfers[0]]

        # Use each member's next digest as the rotation next-key set
        migers = [hab1.kever.ndigers[0], hab2.kever.ndigers[0]]
        rot = ghab1.rotate(isith="2", nsith="2", toad=0, cuts=[], adds=[],
                           verfers=merfers, digers=migers,
                           framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)

        # Keep the rotation serder so later assertions can use its prefix and SAID
        rotSerder = SerderKERI(raw=rot)

        # Seed the mux with the local /multisig/rot approval
        localRotExn, localRotAtc = multisigRotateExn(ghab=ghab1, smids=ghab1.smids,
                                                     rmids=ghab1.rmids, rot=rot,
                                                     version=Vrsn_2_0, kind=Kinds.json)

        # Parse locally without processing so we can pass the V2 nested child into mux.add
        localRot = Parser(version=Vrsn_2_0).parse(ims=bytearray(localRotExn.raw + localRotAtc),
                                                  framed=True,
                                                  processive=False)[0]
        mux.add(localRot.serder, nests=localRot.nests)

        # Start counselor tracking for the inner group rotation event
        rotNumber = Number(sn=1)
        rotDiger = Diger(qb64=rotSerder.said)
        counselor.start(ghab=ghab1, prefixer=prefixer, number=rotNumber, diger=rotDiger)

        # Have the remote participant add its own signature to the same agreed child rotation.
        # This mirrors the existing partial-group-rotation tests: the remote side contributes
        # the second signature on the child event, then wraps that signed child in its own EXN.
        sigers = hab2.mgr.sign(rotSerder.raw,
                               verfers=hab2.kever.verfers,
                               indexed=True,
                               indices=[1],
                               ondices=[1])

        # Package the remote signature with the same child rotation event.
        remoteRot = messagize(serder=rotSerder, sigers=sigers,
                               framed=True, gvrsn=Vrsn_2_0)

        # Wrap that signed child in a V2 /multisig/rot EXN and send it through the exchanger path
        remoteRotExn, remoteRotAtc = multisigRotateExn(ghab=ghab2, smids=ghab1.smids,
                                                       rmids=ghab1.rmids, rot=remoteRot,
                                                       version=Vrsn_2_0, kind=Kinds.json)

        # Incoming remote approval should replay the nested rotation and merge its signature
        Parser(version=Vrsn_2_0).parse(ims=bytearray(remoteRotExn.raw + remoteRotAtc),
                                       exc=exc,
                                       local=False)

        # Process the resulting inner group-event escrows so the second signature is applied
        mux.kvy.processEscrows()

        # The shared child rotation should now carry both signatures locally
        rotSigers = hby1.db.sigs.get(keys=(rotSerder.preb, rotSerder.saidb))
        assert [siger.index for siger in rotSigers] == [0, 1]

        # With the second signature replayed, the group rotation itself should anchor at sn=1 in the KEL
        assert hby1.db.kels.getLast(keys=ghab1.pre, on=1) == rotSerder.said

        # The counselor should also be able to observe completion of the rotation lifecycle
        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, number=rotNumber, diger=rotDiger)

        # The inner rotation should now be anchored in the group KEL at sequence number 1
        assert hby1.db.kels.getLast(keys=ghab1.pre, on=1) == rotSerder.said
        assert ghab1.kever.sn == 1

        # Finally, confirm the counselor sees the rotation lifecycle as complete too
        counselor.processEscrows()
        assert counselor.complete(prefixer=prefixer, number=rotNumber, diger=rotDiger)


def test_hab_exchange_v2_embeds_not_supported(mockHelpingNowUTC):
    kwa = dict(version=Vrsn_2_0, kind=Kinds.json)
    with openHby(salt=Salter(raw=b'0123456789abcdef').qb64, version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test", **kwa)

        evtA = hab.exchange(route="/echo/A",
                            attributes=dict(msg="A"),
                            framed=True,
                            gvrsn=Vrsn_2_0,
                            **kwa)
        evtB = hab.exchange(route="/echo/B",
                            attributes=dict(msg="B"),
                            framed=True,
                            gvrsn=Vrsn_2_0,
                            **kwa)

        embeds = dict(
            evtA=evtA,
            evtB=evtB,
        )

        data = dict(m="Let's send two events")
        with pytest.raises(ValueError):
            hab.exchange(route="/forward/multi",
                         attributes=data,
                         embeds=embeds,
                         framed=True,
                         gvrsn=Vrsn_2_0,
                         **kwa)


if __name__ == "__main__":
    test_nesting()
    test_essrs()
    #test_hab_exchange(mockHelpingNowUTC)
