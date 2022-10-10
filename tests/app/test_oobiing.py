# -*- encoding: utf-8 -*-
"""
tests.app.test_multisig module

"""
import json

import falcon
from falcon import testing
from hio.base import doing

import keri
from keri.app import habbing, oobiing, notifying
from keri.db import basing
from keri.help import helping
from keri.peer import exchanging

from tests.app import openMultiSig


def test_oobi_share(mockHelpingNowUTC):
    oobi = "http://127.0.0.1:5642/oobi/Egw3N07Ajdkjvv4LB2Mhx2qxl6TOCFdWNJU6cYR_ImFg/witness" \
           "/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo?name=Phil"
    with habbing.openHab(name="test", temp=True) as (hby, hab):
        exc = exchanging.Exchanger(db=hby.db, handlers=[])
        notifier = notifying.Notifier(hby=hby)

        oobiing.loadHandlers(hby=hby, exc=exc, notifier=notifier)

        assert "/oobis" in exc.routes

        handler = exc.routes["/oobis"]
        msg = dict(
            pre=hab.kever.prefixer,
            payload=dict(
                oobi=oobi
            ))
        handler.msgs.append(msg)

        limit = 1.0
        tock = 0.25
        doist = doing.Doist(limit=limit, tock=tock)
        doist.do(doers=[handler])
        assert doist.tyme == limit

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

        msg = dict(
            pre=hab.kever.prefixer,
            payload=dict(
            ))
        handler.msgs.append(msg)

        limit = 1.0
        tock = 0.25
        doist = doing.Doist(limit=limit, tock=tock)
        doist.do(doers=[handler])
        assert doist.tyme == limit
        assert len(notifier.signaler.signals) == 0

        exn, atc = oobiing.oobiRequestExn(hab=hab, dest="EO2kxXW0jifQmuPevqg6Zpi3vE-WYoj65i_XhpruWtOg",
                                          oobi="http://127.0.0.1/oobi")
        assert exn.ked == {'a': {'dest': 'EO2kxXW0jifQmuPevqg6Zpi3vE-WYoj65i_XhpruWtOg',
                                 'oobi': 'http://127.0.0.1/oobi'},
                           'd': 'EHuKAScxCSm3v8ooWR2wIilGul_ZUwHAXt63Y5bhfvmt',
                           'dt': '2021-01-01T00:00:00.000000+00:00',
                           'q': {},
                           'r': '/oobis',
                           't': 'exn',
                           'v': 'KERI10JSON0000ed_'}
        assert atc == (b'-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAACS1e3y_nIO'
                       b'l5UQAtrq2O9w-CaYTNTSDNjBK5k01nUFkV4yiHo-HE40nVsjrb9uKQYAHTaRVTUo'
                       b'nj3KashCBTMP')


def test_oobi_share_endpoint():
    with openMultiSig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)):
        app = falcon.App()
        oobiEnd = oobiing.OobiResource(hby=hby1)
        app.add_route("/oobi/groups/{alias}/share", oobiEnd, suffix="share")
        client = testing.TestClient(app)

        body = dict(oobis=[
            "http://127.0.0.1:3333/oobi",
            "http://127.0.0.1:5555/oobi",
            "http://127.0.0.1:7777/oobi"
        ])
        raw = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path="/oobi/groups/test_1/share", body=raw)
        assert result.status == falcon.HTTP_400
        result = client.simulate_post(path="/oobi/groups/fake/share", body=raw)
        assert result.status == falcon.HTTP_404
        result = client.simulate_post(path="/oobi/groups/test_group1/share", body=raw)
        assert result.status == falcon.HTTP_200

        # Assert that a message has been send to each participant for each OOBI
        assert len(oobiEnd.postman.evts) == 6


def test_oobiery():
    with habbing.openHby(name="oobi") as hby:
        oobiery = keri.app.oobiing.Oobiery(hby=hby)

        url = 'http://127.0.0.1:5644/oobi/EADqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness' \
              '/BAyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw?name=jim'
        obr = basing.OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)
        url = 'http://127.0.0.1:5644/oobi/EBRzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0'
        obr = basing.OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)
        url = 'http://127.0.0.1:5644/.well-known/keri/oobi?name=Root'
        obr = basing.OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)
        url = 'http://127.0.0.1:5644/oobi?name=Blind'
        obr = basing.OobiRecord(date=helping.nowIso8601())
        hby.db.oobis.pin(keys=(url,), val=obr)

        app = falcon.App()  # falcon.App instances are callable WSGI apps
        endDoers = oobiing.loadEnds(app, hby=hby)

        limit = 2.0
        tock = 0.03125
        doers = endDoers + oobiery.doers
        doist = doing.Doist(limit=limit, tock=tock)
        doist.do(doers=doers)

        assert doist.limit == limit

        doist.exit()

    """Done Test"""


def test_authenticator(mockHelpingNowUTC):
    with habbing.openHby(name="oobi") as hby:
        authn = keri.app.oobiing.Authenticator(hby=hby)

        url = 'http://127.0.0.1:5644/.well-known/keri/oobi/EN9CoGmdCd8fNaYK3FrYUJhmJHL7aZ3OhFZzEutJ5xZZ?name=Root'
        obr = basing.OobiRecord(date=helping.nowIso8601())
        hby.db.woobi.pin(keys=(url,), val=obr)
        url = 'http://127.0.0.1:5644/oobi/EBRzmSCFmG2a5U2OqZF-yUobeSYkW-a3FsN82eZXMxY0'
        obr = basing.OobiRecord(date=helping.nowIso8601())
        hby.db.woobi.pin(keys=(url,), val=obr)

        app = falcon.App()  # falcon.App instances are callable WSGI apps
        endDoers = oobiing.loadEnds(app, hby=hby)

        limit = 2.0
        tock = 0.03125
        doers = endDoers + authn.doers
        doist = doing.Doist(limit=limit, tock=tock)
        doist.do(doers=doers)

        assert doist.limit == limit

        doist.exit()

