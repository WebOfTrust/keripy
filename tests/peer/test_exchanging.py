# -*- encoding: utf-8 -*-
"""
tests.peer.test_exchanging module

"""
from keri.app import habbing, forwarding, storing, signing
from keri.core import coring, serdering
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
    with habbing.openHby() as hby:
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
        assert msg == (b'{"v":"KERI10JSON0003a0_","t":"exn","d":"ELkHqph-Tj4LGHYfFfoVmJJo09S2gp6ci8rK96upIAKE",'
                       b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"","p":"",'
                       b'"dt":"2021-01-01T00:00:00.000000+00:00","r":"/multisig/registry/incept","q":{},"a":{"i":"",'
                       b'"m":"Let\'s create a registry"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp",'
                       b'"d":"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB",'
                       b'"i":"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB",'
                       b'"ii":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"0","c":[],"bt":"0","b":[],'
                       b'"n":"AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"ixn":{"v":"KERI10JSON000138_",'
                       b'"t":"ixn","d":"EFuFnevyDFfpWG6il-6Qcv0ne0ZIItLwanCwI-SU8A9j",'
                       b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"1",'
                       b'"p":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3",'
                       b'"a":[{"i":"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB","s":0,'
                       b'"d":"EI6hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB"}]},'
                       b'"d":"EL5Nkm6T7HG_0GW6uwqYSZwlH23khtXvsVE-dq8eO_eE"}}-FABEIaGMMWJFPmtXznY1IIiKDIrg'
                       b'-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'
                       b'-AABAAB-teJc_7zot5TAZT6lQi2-GlBzMHXICvt3tIYoPo2gYXF7PpWDozo3y3wVW9mgHln-1DvQlqn9Aip1YnBgKUQB'
                       b'-LAa5AACAA-e-ixn-AABAADprTWp4llIzVzBM7VVsDOgXVJdoiVXutsWJEbDJ2pMdjXjNi1xKALBSZ1ZgRoUsD'
                       b'--LgUQkXIdjLoQ19XPvJMJ')

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
        assert msg == (b'{"v":"KERI10JSON0003d6_","t":"exn","d":"EPO_XC9nwSixqSoOvsHymFr-l3udclHBdOh4OUEqZ33P",'
                       b'"i":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","rp":"",'
                       b'"p":"ELkHqph-Tj4LGHYfFfoVmJJo09S2gp6ci8rK96upIAKE","dt":"2021-01-01T00:00:00.000000+00:00",'
                       b'"r":"/multisig/registry/incept","q":{},"a":{"i":"","m":"Lets create this registry instead"},'
                       b'"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp",'
                       b'"d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB",'
                       b'"i":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB",'
                       b'"ii":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","s":"0","c":[],"bt":"0","b":[],'
                       b'"n":"AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"ixn":{"v":"KERI10JSON000138_",'
                       b'"t":"ixn","d":"EOek9JVKNeuW-5UNeHYCTDe70_GtvRwP672oWMNBJpA5",'
                       b'"i":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","s":"1",'
                       b'"p":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2",'
                       b'"a":[{"i":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","s":0,'
                       b'"d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB"}]},'
                       b'"d":"EM3gLTzQ9GmKd50Rlm_kiIkeYkxb004eoOsWahz70TqJ'
                       b'"}}-FABEIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc20AAAAAAAAAAAAAAAAAAAAAAAEIREQlatUJODbKogZ'
                       b'fa3IqXZ90XdZA0qJMVliI61Bcc2-AABAADY5nUsBgL23ulcrTgkV09hSzktNHZSlEH1zmVpEggrGgQUq0tLQeOXztUFD'
                       b'xNQ4Kq2ddIYDVz6d_y0kkU3__YJ-LAa5AACAA-e-ixn-AABAACaoxfQp5L_Gd0nKqJXMbLTXzkrJJDd8RFxWdTSesAMy'
                       b'dUzmJQlGt0T9h8L7SwIrq8yBinj990PLJHl7sXmq04I')

        # Test exn from non-transferable AID
        hab = hby.makeHab(name="test1", transferable=False)
        assert hab.pre == "BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG"

        embeds = dict(
            vcp=hab.endorse(regser, pipelined=False)
        )
        msg = hab.exchange(route="/multisig/registry/incept", payload=data, embeds=embeds,
                           recipient="")
        assert msg == (b'{"v":"KERI10JSON00026b_","t":"exn","d":"EMBm0p7fCIqJrP4Z-PBI-yEvXin_-eY1dU4XTCM9ykRC",'
                       b'"i":"BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG","rp":"","p":"",'
                       b'"dt":"2021-01-01T00:00:00.000000+00:00","r":"/multisig/registry/incept","q":{},"a":{"i":"",'
                       b'"m":"Lets create this registry instead"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp",'
                       b'"d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB",'
                       b'"i":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB",'
                       b'"ii":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","s":"0","c":[],"bt":"0","b":[],'
                       b'"n":"AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},'
                       b'"d":"ENC6w8wUj-Gp_RpAJN5q4Lf00IHstzNLUvkh3ZvgHGP_"}}-CABBJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6'
                       b'-tFVlCeiZPG0BB-sQs0WS9wsyuT4hXQD7rbczSfpnQz21wZGYucRkE0ynKy5draELEKBsckeD0Im1i'
                       b'-kIfMEdbY08YqVfSrEoAA-LAl5AACAA-e-vcp-CABBJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6'
                       b'-tFVlCeiZPG0BDjOC4j0Co6P0giMylR47149eJ8Yf_hO'
                       b'-32_TpY77KMVCWCf0U8GuZPIN76R2zsyT_eARvS_zQsX1ebjl3PMP0D')
