# -*- encoding: utf-8 -*-
"""
tests.peer.test_exchanging module

"""

from keri.app import habbing, forwarding, storing, signing
from keri.core import coring
from keri.peer import exchanging
from keri.vdr.eventing import incept


def test_exchanger():
    with habbing.openHab(name="sid", base="test", salt=b'0123456789abcdef') as (hby, hab):
        mbx = storing.Mailboxer(hby=hby)
        forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)
        exc = exchanging.Exchanger(db=hby.db, handlers=[forwarder])

        ser, sigs, _ = hab.getOwnEvent(sn=0)
        sadsig = signing.SadPathSigGroup(pather=coring.Pather(path=[]), sigers=sigs)
        act = bytearray()
        pather = coring.Pather(path=["e"])
        sadsig.transpose(pather)
        act.extend(sadsig.proof)

        # create the forward message with payload embedded at `a` field
        fwd = exchanging.exchange(route='/fwd', sender=hab.pre,
                                  modifiers=dict(pre="EBCAFG", topic="/delegation"),
                                  payload={}, embeds=dict(evt=ser.ked))
        exnsigs = hab.sign(ser=fwd.raw,
                           verfers=hab.kever.verfers,
                           indexed=True)
        tsgs = [(hab.kever.prefixer, coring.Seqner(sn=hab.kever.sn), hab.kever.serder.saider, exnsigs)]
        exc.processEvent(serder=fwd, source=hab.kever.prefixer, tsgs=tsgs,
                         sadsigs=[(sadsig.pather, sadsig.sigers)])

        assert len(forwarder.msgs) == 1
        msg = forwarder.msgs.popleft()

        assert msg["payload"] == {}
        assert msg["embeds"]["evt"] == ser.ked
        assert msg["modifiers"] == {'pre': 'EBCAFG', 'topic': '/delegation'}
        assert msg["pre"].qb64b == hab.kever.prefixer.qb64b
        assert msg["attachments"] == []


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
                           payload=data, embeds=embeds, save=True)
        assert msg == (b'{"v":"KERI10JSON000365_","t":"exn","d":"EAcPrjatUJ4NXLPDGE9nNNIR'
                       b'wnqfZ384iaG1kJrV0WJL","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2Q'
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
                       b'ZyfLW35_UyM4nIK44OgsSwFR_WOfvVB"}]}}}-FABEIaGMMWJFPmtXznY1IIiKDI'
                       b'rg-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1II'
                       b'iKDIrg-vIyge6mBl2QV8dDjI3-AABAAAc6mCQTZCglkvtnDLemdmbCKriIm4SWVi'
                       b'9MYAS5064abLrcgp7aGL7RVjIptp-WiImrlsjAOgIz1S_MZUJSnIP-LAa5AACAA-'
                       b'e-ixn-AABAADprTWp4llIzVzBM7VVsDOgXVJdoiVXutsWJEbDJ2pMdjXjNi1xKAL'
                       b'BSZ1ZgRoUsD--LgUQkXIdjLoQ19XPvJMJ')

        exn = coring.Serder(raw=msg)
        serder = hab.db.exns.get(keys=(exn.said,))
        assert serder.ked == exn.ked
        paths = hab.db.epath.get(keys=(serder.said,))
        assert len(paths) == 1

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
        msg = hab2.exchange(route="/multisig/registry/incept", payload=data, recipient="", dig=serder.said,
                            embeds=embeds, save=True)
        assert msg == (b'{"v":"KERI10JSON00039b_","t":"exn","d":"EA_JIghM5IfUYEeuEsqL652U'
                       b'_0Is4GHXjLw5BDU7YtoF","i":"EIREQlatUJODbKogZfa3IqXZ90XdZA0qJMVli'
                       b'I61Bcc2","p":"EAcPrjatUJ4NXLPDGE9nNNIRwnqfZ384iaG1kJrV0WJL","dt"'
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
                       b'dPZ0NSHM1HC3IndbS_giB"}]}}}-FABEIREQlatUJODbKogZfa3IqXZ90XdZA0qJ'
                       b'MVliI61Bcc20AAAAAAAAAAAAAAAAAAAAAAAEIREQlatUJODbKogZfa3IqXZ90XdZ'
                       b'A0qJMVliI61Bcc2-AABAADgV6a96VumoUfijO4zRLmz_W_1h6gM-VWNh4JxIUVeF'
                       b'2TUmdJcDaCVlv2iOgPjwVWr2RKi1WTSTK3i8Esg4UYE-LAa5AACAA-e-ixn-AABA'
                       b'ACaoxfQp5L_Gd0nKqJXMbLTXzkrJJDd8RFxWdTSesAMydUzmJQlGt0T9h8L7SwIr'
                       b'q8yBinj990PLJHl7sXmq04I')
        exn = coring.Serder(raw=msg)
        serder = hab.db.exns.get(keys=(exn.said,))
        assert serder.ked == exn.ked

        paths = hab.db.epath.get(keys=(serder.said,))
        assert len(paths) == 1

        # Test exn from non-transferable AID
        hab = hby.makeHab(name="test1", transferable=False)
        assert hab.pre == "BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG"

        embeds = dict(
            vcp=hab.endorse(regser, pipelined=False)
        )
        msg = hab.exchange(route="/multisig/registry/incept", payload=data, embeds=embeds,
                           recipient="", save=True)
        assert msg == (b'{"v":"KERI10JSON000230_","t":"exn","d":"EIVsFMbmEdf_1meVjVHle18H'
                       b'ynuvW2VRN6m_um6wlk8A","i":"BJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFV'
                       b'lCeiZPG","p":"","dt":"2021-01-01T00:00:00.000000+00:00","r":"/mu'
                       b'ltisig/registry/incept","q":{},"a":{"i":"","m":"Lets create this'
                       b' registry instead"},"e":{"vcp":{"v":"KERI10JSON00010f_","t":"vcp'
                       b'","d":"EB5mts6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","i":"EB5mts'
                       b'6qrWOZrxjma6lSTjAdPZ0NSHM1HC3IndbS_giB","ii":"EIREQlatUJODbKogZf'
                       b'a3IqXZ90XdZA0qJMVliI61Bcc2","s":"0","c":[],"bt":"0","b":[],"n":"'
                       b'AH3-1EZWXU9I0fv3Iz_9ZIhjj13JO7u4GNFYC3-l8_K-"}}}-CABBJZ_LF61JTCC'
                       b'SCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG0BAOW4uFOG5CKDZdx-Tf3nRwFbiMenSN'
                       b'B5PU8Rz8hRxVun57iPGk-Sn3VeMzGm0JrKd3SZau_GL-D6vllNdyYrcJ-LAl5AAC'
                       b'AA-e-vcp-CABBJZ_LF61JTCCSCIw2Q4ozE2MsbRC4m-N6-tFVlCeiZPG0BDjOC4j'
                       b'0Co6P0giMylR47149eJ8Yf_hO-32_TpY77KMVCWCf0U8GuZPIN76R2zsyT_eARvS'
                       b'_zQsX1ebjl3PMP0D')

        serder = hab.db.exns.get(keys=(exn.said,))
        assert serder.ked == exn.ked
