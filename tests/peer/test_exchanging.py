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
    with habbing.openHby(salt=coring.Salter(raw=b'0123456789abcdef').qb64) as hby:
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
        assert msg == (b'{"v":"KERI10JSON000398_","t":"exn","d":"ECcmfGnlqnc5-1_oXNpbfowv'
                       b'RsEa-V8tfeKmQDRJJ50i","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2Q'
                       b'V8dDjI3","p":"","dt":"2021-01-01T00:00:00.000000+00:00","r":"/mu'
                       b'ltisig/registry/incept","q":{},"a":{"i":"","m":"Let\'s create a r'
                       b'egistry"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp","d":"EI6'
                       b'hBlgkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB","i":"EI6hBlgkWoJgkZyf'
                       b'LW35_UyM4nIK44OgsSwFR_WOfvVB","ii":"EIaGMMWJFPmtXznY1IIiKDIrg-vI'
                       b'yge6mBl2QV8dDjI3","s":"0","c":[],"bt":"0","b":[],"n":"AH3-1EZWXU'
                       b'9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"ixn":{"v":"KERI10JSON00013'
                       b'8_","t":"ixn","d":"EFuFnevyDFfpWG6il-6Qcv0ne0ZIItLwanCwI-SU8A9j"'
                       b',"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"1","p":'
                       b'"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","a":[{"i":"EI6hBl'
                       b'gkWoJgkZyfLW35_UyM4nIK44OgsSwFR_WOfvVB","s":0,"d":"EI6hBlgkWoJgk'
                       b'ZyfLW35_UyM4nIK44OgsSwFR_WOfvVB"}]},"d":"EL5Nkm6T7HG_0GW6uwqYSZw'
                       b'lH23khtXvsVE-dq8eO_eE"}}-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2'
                       b'QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6'
                       b'mBl2QV8dDjI3-AABAACahD6g7IwjUyQRyGUPGLvlr5-DsvLxeJtCUVIIECYfAQ_q'
                       b'p3Z2pe__HRqIl-NrUv85oQrZBm0kpKn8LBQtQfkO-LAa5AACAA-e-ixn-AABAADp'
                       b'rTWp4llIzVzBM7VVsDOgXVJdoiVXutsWJEbDJ2pMdjXjNi1xKALBSZ1ZgRoUsD--'
                       b'LgUQkXIdjLoQ19XPvJMJ')

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
        assert msg == (b'{"v":"KERI10JSON0003ce_","t":"exn","d":"EEMxkjO9HzZoekfzmjrkE19y'
                       b'pU259apUWuY7alFu_GmE","i":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVli'
                       b'I61Bcc2","p":"ECcmfGnlqnc5-1_oXNpbfowvRsEa-V8tfeKmQDRJJ50i","dt"'
                       b':"2021-01-01T00:00:00.000000+00:00","r":"/multisig/registry/ince'
                       b'pt","q":{},"a":{"i":"","m":"Lets create this registry instead"},'
                       b'"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp","d":"EB5mts6qrWOZr'
                       b'xjma6lSTjAdPZ0NSHM1HC3IndbS_giB","i":"EB5mts6qrWOZrxjma6lSTjAdPZ'
                       b'0NSHM1HC3IndbS_giB","ii":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI'
                       b'61Bcc2","s":"0","c":[],"bt":"0","b":[],"n":"AH3-1EZWXU9I0fv3Iz_9'
                       b'ZIhjj13JO7u4GNFYC3-l8_K-"},"ixn":{"v":"KERI10JSON000138_","t":"i'
                       b'xn","d":"EOek9JVKNeuW-5UNeHYCTDe70_GtvRwP672oWMNBJpA5","i":"EIRE'
                       b'QlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","s":"1","p":"EIREQlatU'
                       b'JODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc2","a":[{"i":"EB5mts6qrWOZrxjm'
                       b'a6lSTjAdPZ0NSHM1HC3IndbS_giB","s":0,"d":"EB5mts6qrWOZrxjma6lSTjA'
                       b'dPZ0NSHM1HC3IndbS_giB"}]},"d":"EM3gLTzQ9GmKd50Rlm_kiIkeYkxb004eo'
                       b'OsWahz70TqJ"}}-FABEIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bcc20A'
                       b'AAAAAAAAAAAAAAAAAAAAAAEIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVliI61Bc'
                       b'c2-AABAAAxpwQLr9-D7hOZYHvvDB_ffo5sRgBf0NufowF0g_YMI1wdnttlYA2o_d'
                       b'wtK_WNbfh_iAytFw9nHZziCED13AwH-LAa5AACAA-e-ixn-AABAACaoxfQp5L_Gd'
                       b'0nKqJXMbLTXzkrJJDd8RFxWdTSesAMydUzmJQlGt0T9h8L7SwIrq8yBinj990PLJ'
                       b'Hl7sXmq04I')

        # Test exn from non-transferable AID
        hab = hby.makeHab(name="test1", transferable=False)
        assert hab.pre == "BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG"

        embeds = dict(
            vcp=hab.endorse(regser, pipelined=False)
        )
        msg = hab.exchange(route="/multisig/registry/incept", payload=data, embeds=embeds,
                           recipient="")
        assert msg == (b'{"v":"KERI10JSON000263_","t":"exn","d":"ENRFAVDU_ZbcVpx6l6lrC5Mu'
                       b'UqHXfT3N9VjUkvU4t29S","i":"BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFV'
                       b'lCeiZPG","p":"","dt":"2021-01-01T00:00:00.000000+00:00","r":"/mu'
                       b'ltisig/registry/incept","q":{},"a":{"i":"","m":"Lets create this'
                       b' registry instead"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp'
                       b'","d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","i":"EB5mts'
                       b'6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","ii":"EIREQlatUJODbKogZf'
                       b'a3IqXZ90XdZA0qJMVliI61Bcc2","s":"0","c":[],"bt":"0","b":[],"n":"'
                       b'AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"},"d":"ENC6w8wUj-Gp'
                       b'_RpAJN5q4Lf00IHstzNLUvkh3ZvgHGP_"}}-CABBJZ_LF61JTCCSCIw2Q4ozE2Ms'
                       b'bRC4m-N6-tFVlCeiZPG0BCxLApuSnk1MF9IUq1RJNjVmr6s-fLwvP6aAPa0ag34t'
                       b'4G7EKKk-UFwy74-0StSlHcS8KBkN5ZbtuHvV9tXRqUJ-LAl5AACAA-e-vcp-CABB'
                       b'JZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG0BDjOC4j0Co6P0giMylR4'
                       b'7149eJ8Yf_hO-32_TpY77KMVCWCf0U8GuZPIN76R2zsyT_eARvS_zQsX1ebjl3PM'
                       b'P0D')
