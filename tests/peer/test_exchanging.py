# -*- encoding: utf-8 -*-
"""
tests.peer.test_exchanging module

"""
import json

import pysodium

from keri import Kinds, Vrsn_1_0
from keri.core import (Salter, Counter, Texter,
                       Diger, SerderKERI, Parser,
                       MtrDex, Codens, exchange)

from keri.app import openHab, openHby

from keri.peer import Exchanger, nesting, specialExchange
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


if __name__ == "__main__":
    test_nesting()
    test_essrs()
    #test_hab_exchange(mockHelpingNowUTC)
