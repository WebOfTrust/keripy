# -*- encoding: utf-8 -*-
"""
tests.app.test_multisig module

"""

import falcon
from falcon import testing
from hio.base import doing
from hio.core import http

from keri.kering import Vrsn_1_0, Vrsn_2_0, Roles, Schemes, Version, Kinds
from keri.app import (Notifier, Oobiery, Authenticator,
                      Result, openHab, openHby,
                      oobiRequestExn)
from keri.app.oobiing import (loadHandlers as loadOobiingHandlers,
                              loadEnds as loadOobiingEnds)

from keri.core import (SerderKERI, Kevery, Parser,
                       Salter, Router, Revery)

from keri.end.ending import loadEnds as loadEndingEnds
from keri.help import helping
from keri.peer import Exchanger
from keri.recording import OobiRecord

V2 = Vrsn_2_0
from tests.common import KWA


def test_oobi_share_v1(mockHelpingNowUTC):
    oobi = "http://127.0.0.1:5642/oobi/Egw3N07Ajdkjvv4LB2Mhx2qxl6TOCFdWNJU6cYR_ImFg/witness" \
           "/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo?name=Phil"
    with openHab(name="test", temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        exc = Exchanger(hby=hby, handlers=[])
        notifier = Notifier(hby=hby)

        loadOobiingHandlers(hby=hby, exc=exc, notifier=notifier)

        assert "/oobis" in exc.routes
        handler = exc.routes["/oobis"]

        exn, _ = oobiRequestExn(hab, hab.pre, oobi, version=Vrsn_1_0, gvrsn=Vrsn_1_0)

        handler.handle(serder=exn)

        obr = hby.db.oobis.get(keys=(oobi,))
        assert obr is not None

        assert len(notifier.signaler.signals) == 1
        signal = notifier.signaler.signals.popleft()
        assert signal.pad['r'] == '/notification'
        rid = signal.attrs['note']['i']

        note, _ = notifier.noter.get(rid)
        assert note.attrs == {'oobi': 'http://127.0.0.1:5642/oobi/Egw3N07Ajdkjvv4LB2Mhx2qxl6TOCFdWNJU6cYR_ImFg/witness/'
                                      'BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo?name=Phil',
                              'oobialias': 'Phil',
                              'r': '/oobi',
                              'src': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'}

        exn, atc = oobiRequestExn(hab=hab, dest="EO2kxXW0jifQmuPevqg6Zpi3vE-WYoj65i_XhpruWtOg",
                                          oobi="http://127.0.0.1/oobi",
                                          version=Vrsn_1_0,
                                          gvrsn=Vrsn_1_0)
        assert exn.ked == {'a': {'dest': 'EO2kxXW0jifQmuPevqg6Zpi3vE-WYoj65i_XhpruWtOg',
                                 'oobi': 'http://127.0.0.1/oobi'},
                           'd': 'EII7EvdWFqv0jkjRv10t01zAUcRYbjVhZ_yo3VPZEbpS',
                           'dt': '2021-01-01T00:00:00.000000+00:00',
                           'e': {},
                           'i': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                           'p': '',
                           'q': {},
                           'r': '/oobis',
                           'rp': '',
                           't': 'exn',
                           'v': 'KERI10JSON000136_'}
        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3MAAAEIaGMMWJFPmt'
                    b'XznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAABdw3eSw_7BW2o3z1ufxxs1CPgX'
                    b'1TgtJzn-MxvMjLYTidUd8KSxNKbPU9M3A4orYJDMGMIzhabHJmKA4ZIGbcgK')

def test_oobi_share_v2(mockHelpingNowUTC):
    oobi = "http://127.0.0.1:5642/oobi/Egw3N07Ajdkjvv4LB2Mhx2qxl6TOCFdWNJU6cYR_ImFg/witness" \
           "/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo?name=Phil"

    with openHab(name="test", temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        exc = Exchanger(hby=hby, handlers=[])
        notifier = Notifier(hby=hby)

        loadOobiingHandlers(hby=hby, exc=exc, notifier=notifier)

        assert "/oobis" in exc.routes
        handler = exc.routes["/oobis"]

        exn, _ = oobiRequestExn(hab, hab.pre, oobi, version=V2, gvrsn=V2)

        handler.handle(serder=exn)

        obr = hby.db.oobis.get(keys=(oobi,))
        assert obr is not None

        assert len(notifier.signaler.signals) == 1
        signal = notifier.signaler.signals.popleft()
        assert signal.pad['r'] == '/notification'
        rid = signal.attrs['note']['i']

        note, _ = notifier.noter.get(rid)
        assert note.attrs == {'oobi': 'http://127.0.0.1:5642/oobi/Egw3N07Ajdkjvv4LB2Mhx2qxl6TOCFdWNJU6cYR_ImFg/witness/'
                                      'BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo?name=Phil',
                              'oobialias': 'Phil',
                              'r': '/oobi',
                              'src': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'}

        exn, atc = oobiRequestExn(hab=hab, dest="EO2kxXW0jifQmuPevqg6Zpi3vE-WYoj65i_XhpruWtOg",
                                          oobi="http://127.0.0.1/oobi",
                                          version=V2,
                                          gvrsn=V2)
        assert exn.ked == \
        {
            'v': 'KERICAACAACESRAAEA.',
            't': 'exn',
            'd': 'EJBJ3kmqXkcjr5BC_gKjXKG1GBhdutwa2RZLK_YX1z7p',
            'i': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
            'ri': '',
            'x': '',
            'p': '',
            'dt': '2021-01-01T00:00:00.000000+00:00',
            'r': '/oobis',
            'q': {},
            'a': {'dest': 'EO2kxXW0jifQmuPevqg6Zpi3vE-WYoj65i_XhpruWtOg',
                  'oobi': 'http://127.0.0.1/oobi'}
        }
        assert atc == (b'-XAuEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3MAAAEIaGMMWJFPmt'
          b'XznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-KAWAADFS4WFNRm4dR4xm-dpmAn617mwHEbyof199'
          b'bPsKX1uF_zANa_6QBnjDl6L6k_VcMBPzNGDIGBU6N8xLbkYZNsH')


def test_oobiery(unused_tcp_port_factory):
    with openHby(name="oobi", version=Vrsn_1_0) as hby:
        locPort = unused_tcp_port_factory()
        oobiPort = unused_tcp_port_factory()
        hab = hby.makeHab(name="oobi", **KWA)
        msgs = bytearray()
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    stamp=helping.nowIso8601(), **KWA))

        msgs.extend(hab.makeLocScheme(url=f'http://127.0.0.1:{locPort}',
                                      scheme=Schemes.http,
                                      stamp=helping.nowIso8601(), **KWA))
        hab.psr.parse(ims=msgs)

        oobiery = Oobiery(hby=hby)

        # Insert some that will fail
        url = f'http://127.0.0.1:{oobiPort}/oobi/EADqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness' \
              f'/BAyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw?name=jim'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)
        url = f'http://127.0.0.1:{oobiPort}/oobi/EBRzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)
        url = f'http://127.0.0.1:{oobiPort}/oobi?name=Blind'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)

        # Configure the MOOBI rpy URL and the controller URL
        curl = f'http://127.0.0.1:{oobiPort}/oobi/{hab.pre}/controller'
        murl = f'http://127.0.0.1:{oobiPort}/.well-known/keri/oobi/{hab.pre}?name=Root'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(murl,), val=obr)

        app = falcon.App()  # falcon.App instances are callable WSGI apps
        loadEndingEnds(app, hby=hby)
        moobi = MOOBIEnd(hab=hab, url=curl)
        app.add_route(f"/.well-known/keri/oobi/{hab.pre}", moobi)

        server = http.Server(port=oobiPort, app=app)
        httpServerDoer = http.ServerDoer(server=server)

        limit = 2.0
        tock = 0.03125
        doers = oobiery.doers + [httpServerDoer]
        doist = doing.Doist(limit=limit, tock=tock)
        doist.do(doers=doers)

        assert doist.limit == limit

        obr = hby.db.roobi.get(keys=(curl,))
        assert obr is not None
        assert obr.state == Result.resolved
        obr = hby.db.roobi.get(keys=(murl,))
        assert obr is not None
        assert obr.state == Result.resolved

        doist.exit()

    """Done Test"""


def test_oobiery_parser_version_uses_explicit_or_habery_default():
    with openHby(name="oobi-default") as hby:
        oobiery = Oobiery(hby=hby)
        assert oobiery.version == Version
        assert oobiery.parser.version == Version

    with openHby(name="oobi-hby-v1", version=Vrsn_1_0) as hby:
        oobiery = Oobiery(hby=hby)
        assert oobiery.version == Vrsn_1_0
        assert oobiery.parser.version == Vrsn_1_0

    with openHby(name="oobi-v1") as hby:
        oobiery = Oobiery(hby=hby, version=Vrsn_1_0)
        assert oobiery.version == Vrsn_1_0
        assert oobiery.parser.version == Vrsn_1_0


def test_loaded_v1_endpoint_replies_use_stored_reply_framing():
    with openHby(name="oobi-src", version=Vrsn_1_0) as src, \
            openHby(name="oobi-dst", version=Vrsn_1_0) as dst, \
            openHby(name="oobi-dst-v2", version=Vrsn_2_0) as dst2:
        hab = src.makeHab(name="wit", isith="1", icount=1,
                          transferable=False, **KWA)
        msgs = bytearray()
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    stamp=helping.nowIso8601(),
                                    **KWA))
        msgs.extend(hab.makeLocScheme(url="http://127.0.0.1:5555",
                                      scheme=Schemes.http,
                                      stamp=helping.nowIso8601(),
                                      **KWA))
        hab.psr.parse(ims=msgs)

        oobi = bytearray()
        oobi.extend(hab.replay(version=Vrsn_1_0))
        oobi.extend(hab.loadEndRole(cid=hab.pre,
                                    eid=hab.pre,
                                    role=Roles.controller))
        oobi.extend(hab.loadLocScheme(eid=hab.pre,
                                      scheme=Schemes.http))

        dst.psr.parse(ims=oobi)

        locer = dst.db.locs.get(keys=(hab.pre, Schemes.http))
        assert locer is not None
        assert locer.url == "http://127.0.0.1:5555"

        oobi = hab.replyToOobi(aid=hab.pre,
                               role=Roles.controller,
                               eids=[hab.pre],
                               pvrsn=Vrsn_2_0,
                               kind=Kinds.json,
                               gvrsn=Vrsn_2_0)
        dst2.psr.parse(ims=oobi)

        assert not oobi
        locer = dst2.db.locs.get(keys=(hab.pre, Schemes.http))
        assert locer is not None
        assert locer.url == "http://127.0.0.1:5555"


def test_v2_reply_to_oobi_replay_without_explicit_gvrsn():
    """replyToOobi replay uses target kever pvrsn when gvrsn is omitted."""
    v2kwa = dict(version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
    with openHby(name="oobi-src-v2-replay", version=Vrsn_2_0) as src, \
            openHby(name="oobi-dst-v2-replay", version=Vrsn_2_0) as dst:
        hab = src.makeHab(name="wit", isith="1", icount=1,
                          transferable=False, version=Vrsn_2_0, kind=Kinds.cesr)
        msgs = bytearray()
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    stamp=helping.nowIso8601(),
                                    **v2kwa))
        msgs.extend(hab.makeLocScheme(url="http://127.0.0.1:5555",
                                      scheme=Schemes.http,
                                      stamp=helping.nowIso8601(),
                                      **v2kwa))
        hab.psr.parse(ims=msgs)

        oobi = hab.replyToOobi(aid=hab.pre,
                               role=Roles.controller,
                               eids=[hab.pre])
        assert oobi

        rtr = Router()
        rvy = Revery(db=dst.db, rtr=rtr)
        kvy = Kevery(db=dst.db, lax=False, local=False, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        Parser(version=Vrsn_2_0, kvy=kvy, rvy=rvy).parse(ims=bytearray(oobi))

        assert hab.pre in kvy.kevers
        ender = dst.db.ends.get(keys=(hab.pre, Roles.controller, hab.pre))
        assert ender is not None
        assert ender.allowed is True
        locer = dst.db.locs.get(keys=(hab.pre, Schemes.http))
        assert locer is not None
        assert locer.url == "http://127.0.0.1:5555"


def test_loaded_v2_oobi_endpoint_replies_bypass_kram(mockHelpingNowUTC):
    config = {
        "kram": {
            "enabled": True,
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        }
    }

    with openHby(name="oobi-src-v2", version=Vrsn_2_0) as src, \
            openHby(name="oobi-dst-v2", version=Vrsn_2_0) as dst:
        hab = src.makeHab(name="wit", isith="1", icount=1,
                          transferable=False, version=Vrsn_2_0, kind=Kinds.cesr)
        msgs = bytearray()
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    stamp=helping.nowIso8601(),
                                    version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0))
        msgs.extend(hab.makeLocScheme(url="http://127.0.0.1:5555",
                                      scheme=Schemes.http,
                                      stamp=helping.nowIso8601(),
                                      version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0))
        hab.psr.parse(ims=msgs)

        dst.cf.put(config)
        rtr = Router()
        rvy = Revery(db=dst.db, rtr=rtr)
        kvy = Kevery(db=dst.db, cf=dst.cf, enableKram=True,
                     lax=False, local=False, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        prs = Parser(framed=True, kvy=kvy, rvy=rvy, version=Vrsn_2_0)

        # Assert Kramer is enabled
        assert kvy.kramer is not None
        assert kvy.kramer.enabled is True

        # Create record calls and seen lists to track functions
        calls = []
        seen = []

        # Retrieve kramit and processReply functions to wrap and track calls
        original_kramit = kvy.kramer.kramit
        original_processReply = rvy.processReply

        def kramit(msg, kwa=None):
            calls.append((msg.ilk, msg.route))
            return original_kramit(msg, kwa)

        def processReply(serder, *args, **kwa):
            seen.append((serder.route, serder.pvrsn))
            return original_processReply(serder, *args, **kwa)

        kvy.kramer.kramit = kramit
        rvy.processReply = processReply

        oobi = bytearray()
        oobi.extend(hab.loadEndRole(cid=hab.pre,
                                    eid=hab.pre,
                                    role=Roles.controller))
        oobi.extend(hab.loadLocScheme(eid=hab.pre,
                                      scheme=Schemes.http))

        prs.parse(ims=oobi)

        ender = dst.db.ends.get(keys=(hab.pre, Roles.controller, hab.pre))
        assert ender is not None
        assert ender.allowed is True

        locer = dst.db.locs.get(keys=(hab.pre, Schemes.http))
        assert locer is not None
        assert locer.url == "http://127.0.0.1:5555"


        # Assert seen and calls lists
        assert seen == [
            ("/end/role/add", Vrsn_2_0),
            ("/loc/scheme", Vrsn_2_0),
        ]
        assert calls == []
        assert list(dst.db.kramMSGC.getTopItemIter()) == []


def test_v2_oobi_get_controller_stream_bypasses_kram(mockHelpingNowUTC):
    config = {
        "kram": {
            "enabled": True,
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        }
    }

    with openHby(name="oobi-src-v2-http", version=Vrsn_2_0) as src, \
            openHby(name="oobi-dst-v2-http", version=Vrsn_2_0) as dst:
        hab = src.makeHab(name="oobi", isith="1", icount=1,
                          transferable=False, version=Vrsn_2_0, kind=Kinds.cesr)
        msgs = bytearray()
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    stamp=helping.nowIso8601(),
                                    version=Vrsn_2_0, 
                                    kind=Kinds.cesr, 
                                    gvrsn=Vrsn_2_0))
        msgs.extend(hab.makeLocScheme(url="http://127.0.0.1:5555",
                                      scheme=Schemes.http,
                                      stamp=helping.nowIso8601(),
                                      version=Vrsn_2_0, 
                                      kind=Kinds.cesr, 
                                      gvrsn=Vrsn_2_0))
        hab.psr.parse(ims=msgs)

        app = falcon.App()
        loadEndingEnds(app, hby=src, default=hab.pre)
        client = testing.TestClient(app)
        rep = client.simulate_get(f"/oobi/{hab.pre}/controller")

        assert rep.status == falcon.HTTP_OK
        assert rep.content

        dst.cf.put(config)
        rtr = Router()
        rvy = Revery(db=dst.db, rtr=rtr)
        kvy = Kevery(db=dst.db, cf=dst.cf, enableKram=True,
                     lax=False, local=False, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        prs = Parser(framed=True, kvy=kvy, rvy=rvy, version=Vrsn_2_0)

        calls = []
        seen = []
        original_kramit = kvy.kramer.kramit
        original_processReply = rvy.processReply

        def kramit(msg, kwa=None):
            calls.append((msg.ilk, msg.route))
            return original_kramit(msg, kwa)

        def processReply(serder, *args, **kwa):
            seen.append((serder.route, serder.pvrsn))
            return original_processReply(serder, *args, **kwa)

        kvy.kramer.kramit = kramit
        rvy.processReply = processReply

        prs.parse(ims=bytearray(rep.content))

        ender = dst.db.ends.get(keys=(hab.pre, Roles.controller, hab.pre))
        assert ender is not None
        assert ender.allowed is True

        locer = dst.db.locs.get(keys=(hab.pre, Schemes.http))
        assert locer is not None
        assert locer.url == "http://127.0.0.1:5555"

        assert seen == [
            ("/loc/scheme", Vrsn_2_0),
            ("/end/role/add", Vrsn_2_0),
        ]
        assert calls == []
        assert list(dst.db.kramMSGC.getTopItemIter()) == []


def test_introduce(mockHelpingNowUTC):
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salt = Salter(raw=raw).qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'
    # makHab uses stem=name to make different names have differnt AID pre
    with (openHby(name="wat", base="test", salt=salt, version=Vrsn_1_0) as watHby,
          openHby(name="wit", base="test", salt=salt, version=Vrsn_1_0) as witHby):
        # setup Wes's habitat nontrans
        watHab = watHby.makeHab(name='wes', isith="1", icount=1, transferable=False, **KWA)
        assert not watHab.kever.prefixer.transferable
        assert watHab.pre == "BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom"
        watKvy = Kevery(db=watHab.db, lax=False, local=False)
        watPsr = Parser(kvy=watKvy, version=Vrsn_1_0)

        # setup Wok's habitat nontrans
        witHab = witHby.makeHab(name='wok', isith="1", icount=1, transferable=False, **KWA)
        assert not witHab.kever.prefixer.transferable
        assert witHab.pre == "BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX"
        witKvy = Kevery(db=witHab.db, lax=False, local=False)

        rtr = Router()
        rvy = Revery(db=witHby.db, rtr=rtr)
        Oobiery(hby=witHby, rvy=rvy)
        witPsr = Parser(kvy=witKvy, rvy=rvy, version=Vrsn_1_0)
        assert witHby.db.oobis.cnt() == 0

        oobi = f"https://localhost:8989/oobi/{watHab.pre}/controller"
        data = dict(
            cid=watHab.pre,
            oobi=oobi
        )

        msg = watHab.reply(route="/introduce", data=data, gvrsn=Vrsn_1_0, **KWA)
        assert msg == (b'{"v":"KERI10JSON000127_","t":"rpy","d":"EPEU3V7e2d2mhMWVFDS-oC9z'
                       b'Q8DX8t6ELkhINIaYGFNZ","dt":"2021-01-01T00:00:00.000000+00:00","r'
                       b'":"/introduce","a":{"cid":"BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfX'
                       b'GNrFRom","oobi":"https://localhost:8989/oobi/BBVDlgWic_rAf-m_v7v'
                       b'z_VvIYAUPErvZgLTfXGNrFRom/controller"}}-VAi-CABBBVDlgWic_rAf-m_v'
                       b'7vz_VvIYAUPErvZgLTfXGNrFRom0BBqF8yHDeXpzDUNIOsDBGezNBdgHafmOYbQ7'
                       b'qw0R5t89FbLA26RwaA3NF9-dU0JpbNuJs7jiEBYbSGeDkbBDDEM')

        witPsr.parseOne(ims=msg)
        assert witHby.db.oobis.cnt() == 1
        obr = witHby.db.oobis.get(keys=(oobi,))
        assert obr.cid == watHab.pre

        # Send one missing fields
        data = dict(cid=watHab.pre)
        msg = watHab.reply(route="/introduce", data=data, gvrsn=Vrsn_1_0, **KWA)
        witPsr.parseOne(ims=msg)
        assert witHby.db.oobis.cnt() == 1  # Still one because of the missing 'oobi' field

        # Send one bad scheme
        data = dict(cid=watHab.pre, oobi="ftp://localhost")
        msg = watHab.reply(route="/introduce", data=data, gvrsn=Vrsn_1_0, **KWA)
        witPsr.parseOne(ims=msg)
        assert witHby.db.oobis.cnt() == 1  # Still one because of the missing 'oobi' field





class MOOBIEnd:
    """ Test endpoint returning a static MOOBI """
    def __init__(self, hab, url):
        self.hab = hab
        self.url = url

    def on_get(self, req, rep):
        """ Return controller rpy message with embedded controller OOBI

        Args:
            req (Request): Falcon request object
            rep (Response): Falcon response object

        """
        a = {
            "urls": [
                self.url
            ],
            "aid": self.hab.pre
        }

        rpy = self.hab.reply(route="/oobi/controller", data=a, gvrsn=Vrsn_1_0, **KWA)
        ser = SerderKERI(raw=rpy)
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = ser.raw


def test_authenticator(mockHelpingNowUTC):
    with openHby(name="oobi") as hby:
        authn = Authenticator(hby=hby)

        url = 'http://127.0.0.1:5644/.well-known/keri/oobi/EN9CoGmdCd8fNaYK3FrYUJhmJHL7aZ3OhFZzEutJ5xZZ?name=Root'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.woobi.pin(keys=(url,), val=obr)
        url = 'http://127.0.0.1:5644/oobi/EBRzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.woobi.pin(keys=(url,), val=obr)

        app = falcon.App()  # falcon.App instances are callable WSGI apps
        loadOobiingEnds(app, hby=hby)

        limit = 2.0
        tock = 0.03125
        doers = authn.doers
        doist = doing.Doist(limit=limit, tock=tock)
        doist.do(doers=doers)

        assert doist.limit == limit

        doist.exit()
