# -*- encoding: utf-8 -*-
"""
tests.peer.test_exchanging module

"""
import pysodium
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

from keri import core
from keri.core import coring, serdering, MtrDex, parsing

from keri.app import habbing, forwarding, storing, signing
from keri.core.coring import CtrDex

from keri.peer import exchanging
from keri.vdr.eventing import incept


def test_nesting():
    paths = ['a']
    val = "-JAbccDefg"
    pathed = dict()

    np = exchanging.nesting(paths, pathed, val)
    assert np == pathed
    assert pathed == {'a': '-JAbccDefg'}

    paths = ['a', 'b']
    val = "-JAbccDefg"
    pathed = dict()

    np = exchanging.nesting(paths, pathed, val)
    assert np == pathed
    assert pathed == {'a': {'b': '-JAbccDefg'}}

    paths = ['a', 'b', 'c', 'd', 'e']
    val = "-JAbccDefg"
    pathed = dict()

    np = exchanging.nesting(paths, pathed, val)
    assert np == pathed
    assert pathed == {'a': {'b': {'c': {'d': {'e': '-JAbccDefg'}}}}}

    paths = []
    val = "-JAbccDefg"
    pathed = dict()

    np = exchanging.nesting(paths, pathed, val)
    assert np == val
    assert pathed == {}


def test_essrs():
    with habbing.openHab(name="sid", base="test", salt=b'0123456789abcdef') as (hby, hab), \
            habbing.openHab(name="rec", base="test", salt=b'0123456789abcdef') as (recHby, recHab):

        ims = hab.makeOwnInception()
        parsing.Parser().parse(ims=ims, kvy=recHby.kvy)
        # create the test message with essr attachment
        msg = "This is a test message that must be secured"
        rkever = recHab.kever
        pubkey = pysodium.crypto_sign_pk_to_box_pk(rkever.verfers[0].raw)
        raw = pysodium.crypto_box_seal(msg.encode("utf-8"), pubkey)

        texter = coring.Texter(raw=raw)
        diger = coring.Diger(ser=raw, code=MtrDex.Blake3_256)
        essr, _ = exchanging.exchange(route='/essr/req', sender=hab.pre, diger=diger,
                                      modifiers=dict(src=hab.pre, dest=recHab.pre))
        ims = hab.endorse(serder=essr, pipelined=False)
        ims.extend(coring.Counter(code=CtrDex.ESSRPayloadGroup, count=1).qb64b)
        ims.extend(texter.qb64b)

        exc = exchanging.Exchanger(hby=recHby, handlers=[])
        parsing.Parser().parse(ims=ims, kvy=recHby.kvy, exc=exc)

        # Pull the logged exn and verify the attributes digest matches the attachment
        serder = recHby.db.exns.get(keys=(essr.said,))
        assert serder.ked['a'] == diger.qb64

        # Pull the logged ESSR attachment and verify it is the one attached
        texter = recHby.db.essrs.get(keys=(serder.said,))
        raw = recHab.decrypt(texter[0].raw)
        assert raw.decode("utf-8") == msg

        # Test with invalid diger
        diger = coring.Diger(qb64="EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o")
        essr, _ = exchanging.exchange(route='/essr/req', sender=hab.pre, diger=diger,
                                      modifiers=dict(src=hab.pre, dest=recHab.pre))
        ims = hab.endorse(serder=essr, pipelined=False)
        ims.extend(coring.Counter(code=CtrDex.ESSRPayloadGroup, count=1).qb64b)
        ims.extend(texter[0].qb64b)

        parsing.Parser().parse(ims=ims, kvy=recHby.kvy, exc=exc)
        assert recHby.db.exns.get(keys=(essr.said,)) is None



def test_exchanger():
    with habbing.openHab(name="sid", base="test", salt=b'0123456789abcdef') as (hby, hab), \
            habbing.openHab(name="rec", base="test", salt=b'0123456789abcdef') as (recHby, recHab):
        mbx = storing.Mailboxer(hby=hby)
        forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)
        exc = exchanging.Exchanger(hby=recHby, handlers=[forwarder])

        msg = hab.makeOwnInception()
        recHab.psr.parseOne(ims=msg)

        ser, sigs, _ = hab.getOwnEvent(sn=0)

        sadsig = signing.SadPathSigGroup(pather=coring.Pather(path=[]), sigers=sigs)
        act = bytearray()
        pather = coring.Pather(path=["e"])
        sadsig.transpose(pather)
        act.extend(sadsig.proof)

        # create the forward message with payload embedded at `a` field
        fwd, _ = exchanging.exchange(route='/fwd', sender=hab.pre,
                                     modifiers=dict(pre="EBCAFG", topic="/delegation"),
                                     payload={}, embeds=dict(evt=ser.raw))
        exnsigs = hab.sign(ser=fwd.raw,
                           verfers=hab.kever.verfers,
                           indexed=True)
        tsgs = [(hab.kever.prefixer, coring.Seqner(sn=hab.kever.sn), coring.Saider(qb64=hab.kever.serder.said), exnsigs)]
        exc.processEvent(serder=fwd, source=hab.kever.prefixer, tsgs=tsgs)

        msgs = forwarder.mbx.getTopicMsgs(topic="EBCAFG/delegation")
        assert len(msgs) == 0  # No pathed argument, so nothing to forward.


def test_hab_exchange(mockHelpingNowUTC):
    with habbing.openHby(salt=core.Salter(raw=b'0123456789abcdef').qb64) as hby:
        hab = hby.makeHab(name="test")
        assert hab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        nonce = "AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"
        regser = incept(hab.pre,
                        baks=[],
                        toad=0,
                        cnfg=[],
                        nonce=nonce,
                        code=coring.MtrDex.Blake3_256)
        seal = dict(i=regser.pre, s=regser.sn, d=regser.said)
        msg = hab.interact(data=[seal])

        embeds = dict(
            vcp=regser.raw,
            ixn=msg,
        )

        data = dict(m="Let's create a registry")
        msg = hab.exchange(route="/multisig/registry/incept", recipient="",
                           payload=data, embeds=embeds)
        assert msg == (b'{"v":"KERI10JSON0003a0_","t":"exn","d":"ELkHqph-Tj4LGHYfFfoVmJJo'
                       b'09S2gp6ci8rK96upIAKE","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2Q'
                       b'V8dDjI3","rp":"","p":"","dt":"2021-01-01T00:00:00.000000+00:00",'
                       b'"r":"/multisig/registry/incept","q":{},"a":{"i":"","m":"Let\'s cr'
                       b'eate a registry"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp",'
                       b'"d":"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB","i":"EI6hBlgk'
                       b'WoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB","ii":"EIaGMMWJFPmtXznY1IIi'
                       b'KDIrg-vIyge6mBl2QV8dDjI3","s":"0","c":[],"bt":"0","b":[],"n":"AH'
                       b'3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"ixn":{"v":"KERI10J'
                       b'SON000138_","t":"ixn","d":"EFuFnevyDFfpWG6il-6Qcv0ne0ZIItLwanCwI'
                       b'-SU8A9j","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":'
                       b'"1","p":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","a":[{"i"'
                       b':"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB","s":0,"d":"EI6hB'
                       b'lgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB"}]},"d":"EL5Nkm6T7HG_0GW'
                       b'6uwqYSZwlH23khtXvsVE-dq8eO_eE"}}-FABEIaGMMWJFPmtXznY1IIiKDIrg-vI'
                       b'yge6mBl2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1IIiKDIr'
                       b'g-vIyge6mBl2QV8dDjI3-AABAAB-teJc_7zot5TAZT6lQi2-GlBzMHXICvt3tIYo'
                       b'Po2gYXF7PpWDozo3y3wVW9mgHln-1DvQlqn9Aip1YnBgKUQB-LAa5AACAA-e-ixn'
                       b'-AABAADprTWp4llIzVzBM7VVsDOgXVJdoiVXutsWJEbDJ2pMdjXjNi1xKALBSZ1Z'
                       b'gRoUsD--LgUQkXIdjLoQ19XPvJMJ')

        exn = serdering.SerderKERI(raw=msg)

        hab2 = hby.makeHab(name="respondant")
        regser = incept(hab2.pre,
                        baks=[],
                        toad=0,
                        cnfg=[],
                        nonce=nonce,
                        code=coring.MtrDex.Blake3_256)

        seal = dict(i=regser.pre, s=regser.sn, d=regser.said)
        msg = hab2.interact(data=[seal])

        embeds = dict(
            vcp=regser.raw,
            ixn=msg,
        )

        data = dict(m="Lets create this registry instead")
        msg = hab2.exchange(route="/multisig/registry/incept", payload=data, recipient="", dig=exn.said,
                            embeds=embeds)
        assert msg == (b'{"v":"KERI10JSON0003d6_","t":"exn","d":"EPO_XC9nwSixqSoOvsHymFr-'
                       b'l3udclHBdOh4OUEqZ33P","i":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVli'
                       b'I61Bcc2","rp":"","p":"ELkHqph-Tj4LGHYfFfoVmJJo09S2gp6ci8rK96upIA'
                       b'KE","dt":"2021-01-01T00:00:00.000000+00:00","r":"/multisig/regis'
                       b'try/incept","q":{},"a":{"i":"","m":"Lets create this registry in'
                       b'stead"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp","d":"EB5mt'
                       b's6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","i":"EB5mts6qrWOZrxjma6'
                       b'lSTjAdPZ0NSHM1HC3IndbS_giB","ii":"EIREQlatUJODbKogZfa3IqXZ90XdZA'
                       b'0qJMVliI61Bcc2","s":"0","c":[],"bt":"0","b":[],"n":"AH3-1EZWXU9I'
                       b'0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"ixn":{"v":"KERI10JSON000138_'
                       b'","t":"ixn","d":"EOek9JVKNeuW-5UNeHYCTDe70_GtvRwP672oWMNBJpA5","'
                       b'i":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","s":"1","p":"E'
                       b'IREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","a":[{"i":"EB5mts6q'
                       b'rWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","s":0,"d":"EB5mts6qrWOZrxj'
                       b'ma6lSTjAdPZ0NSHM1HC3IndbS_giB"}]},"d":"EM3gLTzQ9GmKd50Rlm_kiIkeY'
                       b'kxb004eoOsWahz70TqJ"}}-FABEIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI'
                       b'61Bcc20AAAAAAAAAAAAAAAAAAAAAAAEIREQlatUJODbKogZfa3IqXZ90XdZA0qJM'
                       b'VliI61Bcc2-AABAADY5nUsBgL23ulcrTgkV09hSzktNHZSlEH1zmVpEggrGgQUq0'
                       b'tLQeOXztUFDxNQ4Kq2ddIYDVz6d_y0kkU3__YJ-LAa5AACAA-e-ixn-AABAACaox'
                       b'fQp5L_Gd0nKqJXMbLTXzkrJJDd8RFxWdTSesAMydUzmJQlGt0T9h8L7SwIrq8yBi'
                       b'nj990PLJHl7sXmq04I')

        # Test exn from non-transferable AID
        hab = hby.makeHab(name="test1", transferable=False)
        assert hab.pre == "BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG"

        embeds = dict(
            vcp=hab.endorse(regser, pipelined=False)
        )
        msg = hab.exchange(route="/multisig/registry/incept", payload=data, embeds=embeds,
                           recipient="")
        assert msg == (b'{"v":"KERI10JSON00026b_","t":"exn","d":"EMBm0p7fCIqJrP4Z-PBI-yEv'
                       b'Xin_-eY1dU4XTCM9ykRC","i":"BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFV'
                       b'lCeiZPG","rp":"","p":"","dt":"2021-01-01T00:00:00.000000+00:00",'
                       b'"r":"/multisig/registry/incept","q":{},"a":{"i":"","m":"Lets cre'
                       b'ate this registry instead"},"e":{"vcp":{"v":"KERI10JSON00010f_",'
                       b'"t":"vcp","d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","i"'
                       b':"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","ii":"EIREQlatUJ'
                       b'ODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","s":"0","c":[],"bt":"0","b":'
                       b'[],"n":"AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"d":"ENC6'
                       b'w8wUj-Gp_RpAJN5q4Lf00IHstzNLUvkh3ZvgHGP_"}}-CABBJZ_LF61JTCCSCIw2'
                       b'Q4ozE2MsbRC4m-N6-tFVlCeiZPG0BB-sQs0WS9wsyuT4hXQD7rbczSfpnQz21wZG'
                       b'YucRkE0ynKy5draELEKBsckeD0Im1i-kIfMEdbY08YqVfSrEoAA-LAl5AACAA-e-'
                       b'vcp-CABBJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG0BDjOC4j0Co6P'
                       b'0giMylR47149eJ8Yf_hO-32_TpY77KMVCWCf0U8GuZPIN76R2zsyT_eARvS_zQsX'
                       b'1ebjl3PMP0D')
