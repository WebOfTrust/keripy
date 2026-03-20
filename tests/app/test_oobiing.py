# -*- encoding: utf-8 -*-
"""
tests.app.test_multisig module

"""

import falcon
from hio.base import doing
from hio.core import http

from keri.kering import Vrsn_1_0, Roles, Schemes
from keri.app import (Notifier, Oobiery, Authenticator,
                      Result, openHab, openHby,
                      loadOobiingHandlers, oobiRequestExn, loadOobiingEnds)

from keri.core import (SerderKERI, Kevery, Parser,
                       Salter, Router, Revery)

from keri.end import loadEndingEnds
from keri.help import helping
from keri.peer import Exchanger
from keri.recording import OobiRecord


def test_oobi_share(mockHelpingNowUTC):
    oobi = "http://127.0.0.1:5642/oobi/Egw3N07Ajdkjvv4LB2Mhx2qxl6TOCFdWNJU6cYR_ImFg/witness" \
           "/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo?name=Phil"
    with openHab(name="test", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        exc = Exchanger(hby=hby, handlers=[])
        notifier = Notifier(hby=hby)

        loadOobiingHandlers(hby=hby, exc=exc, notifier=notifier)

        assert "/oobis" in exc.routes
        handler = exc.routes["/oobis"]

        exn, _ = oobiRequestExn(hab, hab.pre, oobi)

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
                                          oobi="http://127.0.0.1/oobi")
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
        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAA'
                       b'AAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAABdw3eS'
                       b'w_7BW2o3z1ufxxs1CPgX1TgtJzn-MxvMjLYTidUd8KSxNKbPU9M3A4orYJDMGMIz'
                       b'habHJmKA4ZIGbcgK')


def test_oobiery():
    with openHby(name="oobi") as hby:
        hab = hby.makeHab(name="oobi")
        msgs = bytearray()
        msgs.extend(hab.makeEndRole(eid=hab.pre,
                                    role=Roles.controller,
                                    stamp=helping.nowIso8601()))

        msgs.extend(hab.makeLocScheme(url='http://127.0.0.1:5555',
                                      scheme=Schemes.http,
                                      stamp=helping.nowIso8601()))
        hab.psr.parse(ims=msgs)

        oobiery = Oobiery(hby=hby)

        # Insert some that will fail
        url = 'http://127.0.0.1:5644/oobi/EADqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness' \
              '/BAyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw?name=jim'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)
        url = 'http://127.0.0.1:5644/oobi/EBRzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)
        url = 'http://127.0.0.1:5644/oobi?name=Blind'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)

        # Configure the MOOBI rpy URL and the controller URL
        curl = f'http://127.0.0.1:5644/oobi/{hab.pre}/controller'
        murl = f'http://127.0.0.1:5644/.well-known/keri/oobi/{hab.pre}?name=Root'
        obr = OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(murl,), val=obr)

        app = falcon.App()  # falcon.App instances are callable WSGI apps
        loadEndingEnds(app, hby=hby)
        moobi = MOOBIEnd(hab=hab, url=curl)
        app.add_route(f"/.well-known/keri/oobi/{hab.pre}", moobi)

        server = http.Server(port=5644, app=app)
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


def test_introduce(mockHelpingNowUTC):
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salt = Salter(raw=raw).qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'
    # makHab uses stem=name to make different names have differnt AID pre
    with (openHby(name="wat", base="test", salt=salt) as watHby,
          openHby(name="wit", base="test", salt=salt) as witHby):
        # setup Wes's habitat nontrans
        watHab = watHby.makeHab(name='wes', isith="1", icount=1, transferable=False)
        assert not watHab.kever.prefixer.transferable
        assert watHab.pre == "BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom"
        watKvy = Kevery(db=watHab.db, lax=False, local=False)
        watPsr = Parser(kvy=watKvy, version=Vrsn_1_0)

        # setup Wok's habitat nontrans
        witHab = witHby.makeHab(name='wok', isith="1", icount=1, transferable=False)
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

        msg = watHab.reply(route="/introduce", data=data)
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
        msg = watHab.reply(route="/introduce", data=data)
        witPsr.parseOne(ims=msg)
        assert witHby.db.oobis.cnt() == 1  # Still one because of the missing 'oobi' field

        # Send one bad scheme
        data = dict(cid=watHab.pre, oobi="ftp://localhost")
        msg = watHab.reply(route="/introduce", data=data)
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

        rpy = (self.hab.reply(route="/oobi/controller", data=a))
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