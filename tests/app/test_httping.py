# -*- encoding: utf-8 -*-
"""
tests.peer.httping module

"""

import falcon
import pytest
from falcon.testing import helpers

from keri.app import (openHab, parseCesrHttpRequest,
                      createCESRRequest, streamCESRRequests,
                      CESR_CONTENT_TYPE)
from keri.kering import Ilks, Vrsn_1_0, Vrsn_2_0, Kinds
from keri.core import Kevery, Parser, SerderKERI
from keri.vdr import Regery, Tevery, Verifier

from tests.common import KWA


def test_parse_cesr_request():
    req = helpers.create_req()
    with pytest.raises(falcon.HTTPError):
        parseCesrHttpRequest(req=req)

    req = helpers.create_req(headers=dict(
        Content_Type=CESR_CONTENT_TYPE,
    ))
    with pytest.raises(falcon.HTTPError):
        parseCesrHttpRequest(req=req)

    req = helpers.create_req(headers=dict(
        Content_Type=CESR_CONTENT_TYPE,
        CESR_DATE_HEADER="2021-06-27T21:26:21.233257+00:00",
    ))
    with pytest.raises(falcon.HTTPError):
        parseCesrHttpRequest(req=req)

    req = helpers.create_req(
        headers=dict(
            Content_Type=CESR_CONTENT_TYPE,
            CESR_DATE="2021-06-27T21:26:21.233257+00:00",
        ),
        body='{}',
    )
    with pytest.raises(falcon.HTTPError):
        parseCesrHttpRequest(req=req)

    req = helpers.create_req(
        path="/credential/issue",
        headers=dict(
            Content_Type=CESR_CONTENT_TYPE,
            CESR_DATE="2021-06-27T21:26:21.233257+00:00",
            CESR_ATTACHMENT="-H000000000"
        ),
        body='{"i": 1234}',
    )

    cr = parseCesrHttpRequest(req=req)
    assert cr.payload == dict(i=1234)
    assert cr.attachments == "-H000000000"


class MockRequester:
    path = '/'


class MockClient:

    def __init__(self):
        self.args = []
        self.requester = MockRequester()

    def request(self, **kwargs):
        self.args.append(kwargs)


def test_create_cesr_request(mockHelpingNowUTC):
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", **KWA)

        verfer = Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels", **KWA)
        client = MockClient()

        createCESRRequest(msg, client, dest=wit, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        serder = SerderKERI(raw=args['body'])
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["r"] == "tels"

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == 254
        assert len(headers["CESR-ATTACHMENT"]) == 144

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0), **KWA)
        client = MockClient()

        createCESRRequest(msg, client, dest=wit, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"EPFXeGxCj6VtDCBxgV7HUGF0UxdP9fSZhQw3'
                                b'tWH2TFsY","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == bytearray(
            b'-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB6P97k'
            b'Z3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAz'
            b'qSTBmJzI8RvIezsJ')


def test_create_cesr_request_v2(mockHelpingNowUTC):
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef',
                 version=Vrsn_2_0, kind=Kinds.json) as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", **KWA)

        cf = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                }
            }
        }

        hby.cf.put(cf)
        kvy = Kevery(db=hby.db, cf=hby.cf, enableKram=True, lax=False, local=False)
        tvy = Tevery(db=hby.db, reger=regery.reger, local=False)
        assert kvy.kramer.enabled is True

        verfer = Verifier(hby=hby, reger=regery.reger)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels", version=Vrsn_2_0, kind=Kinds.json)
        client = MockClient()

        createCESRRequest(msg, client, dest=wit, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        serder = SerderKERI(raw=args['body'])
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.json
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["i"] == hab.pre
        assert serder.ked["r"] == "tels"
        assert serder.ked["q"]["i"] == "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4"
        assert serder.ked["q"]["ri"] == issuer.regk
        assert serder.ked["q"]["src"] == hab.pre

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == len(args["body"])
        assert len(headers["CESR-ATTACHMENT"]) > 0

        ims = bytearray(args["body"])
        ims.extend(headers["CESR-ATTACHMENT"])
        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy, tvy=tvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, serder.said))
        assert cache is not None
        assert cache.mdt == serder.stamp
        assert cache.d == 1000

        topics = {"/receipt": 0}
        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query={"topics": topics},
                        version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        client = MockClient()

        createCESRRequest(msg, client, dest=wit, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        serder = SerderKERI(raw=args["body"])
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.json
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["i"] == hab.pre
        assert serder.ked["r"] == "mbx"
        assert serder.ked["q"]["i"] == hab.pre
        assert serder.ked["q"]["src"] == wit
        assert serder.ked["q"]["topics"] == topics

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == 331
        assert len(headers["CESR-ATTACHMENT"]) == 144

        ims = bytearray(args["body"])
        ims.extend(headers["CESR-ATTACHMENT"])
        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, serder.said))
        assert cache is not None
        assert cache.mdt == serder.stamp
        assert cache.d == 1000


def test_stream_cesr_request(mockHelpingNowUTC):
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", **KWA)

        verfer = Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels", **KWA)
        client = MockClient()

        streamCESRRequests(client, msg, dest=wit, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        serder = SerderKERI(raw=args['body'])
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["r"] == "tels"

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == 254
        assert len(headers["CESR-ATTACHMENT"]) == 144

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0), **KWA)
        client = MockClient()

        streamCESRRequests(client, msg, dest=wit, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"EPFXeGxCj6VtDCBxgV7HUGF0UxdP9fSZhQw3'
                                b'tWH2TFsY","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB6P97k'
                                              b'Z3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAz'
                                              b'qSTBmJzI8RvIezsJ')

        msgs = hab.query(pre=hab.pre, src=wit, route="logs", query=dict(s=0), **KWA)
        msgs.extend(hab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_1_0))

        client = MockClient()
        streamCESRRequests(client, msgs, dest=wit)
        assert len(client.args) == 2
        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        assert args["body"] == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2'
                                b'QV8dDjI3","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"0","kt":"1'
                                b'","k":["DGmIfLmgErg4zFHfPwaDckLNxsLqc5iS_P0QbLjbWR0I"],"nt":"1","n":["EJhRr1'
                                b'0e5p7LVB6JwLDIcgqsISktnfe5m60O_I2zZO6N"],"bt":"0","b":[],"c":[],"a":[]}')
        headers = args["headers"]
        assert headers['Content-Length'] == 299
        assert headers['Content-Type'] == 'application/cesr'
        assert headers['CESR-ATTACHMENT'] == (b'-AABAACihaKoLnoXxRoxGbFfOy67YSh6UxtgjT2oxupnLDz2FlhevGJKTMObbdex'
                                              b'9f0Hqob6uTavSJvsXf5RzitskkkC')

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        assert args["body"] == (b'{"v":"KERI10JSON000105_","t":"qry","d":"EHtaQHsKzezkQUEYjMjEv6nIf4AhhR9Zy6Av'
                                b'cfyGCXkI","dt":"2021-01-01T00:00:00.000000+00:00","r":"logs","rr":"","q":{"s'
                                b'":0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8'
                                b'z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')
        headers = args["headers"]
        assert headers['Content-Length'] == 261
        assert headers['Content-Type'] == 'application/cesr'
        assert headers['CESR-ATTACHMENT'] == (b'-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAA9IV9O'
                                              b'7nlInObE0V8E6xphJcv9u_53mP7YFOzESF3RsZOyN_LguuC-ZBBxY_-yjlh-YKeX'
                                              b'jIu5ZwJILbL2bcID')


def test_stream_cesr_request_v2(mockHelpingNowUTC):
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef',
                 version=Vrsn_2_0, kind=Kinds.json) as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test", **KWA)

        cf = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                }
            }
        }

        hby.cf.put(cf)
        kvy = Kevery(db=hby.db, cf=hby.cf, enableKram=True, lax=False, local=False)
        tvy = Tevery(db=hby.db, reger=regery.reger, local=False)
        assert kvy.kramer.enabled is True

        verfer = Verifier(hby=hby, reger=regery.reger)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels", version=Vrsn_2_0, kind=Kinds.json)
        client = MockClient()

        streamCESRRequests(client, msg, dest=wit, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        serder = SerderKERI(raw=args['body'])
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.json
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["i"] == hab.pre
        assert serder.ked["r"] == "tels"
        assert serder.ked["q"]["i"] == "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4"
        assert serder.ked["q"]["ri"] == issuer.regk
        assert serder.ked["q"]["src"] == hab.pre

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == 360
        assert len(headers["CESR-ATTACHMENT"]) == 144

        ims = bytearray(args["body"])
        ims.extend(headers["CESR-ATTACHMENT"])
        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy, tvy=tvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, serder.said))
        assert cache is not None
        assert cache.mdt == serder.stamp
        assert cache.d == 1000

        topics = {"/receipt": 0}
        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query={"topics": topics},
                        version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        client = MockClient()

        streamCESRRequests(client, msg, dest=wit, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        serder = SerderKERI(raw=args["body"])
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.json
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["i"] == hab.pre
        assert serder.ked["r"] == "mbx"
        assert serder.ked["q"]["i"] == hab.pre
        assert serder.ked["q"]["src"] == wit
        assert serder.ked["q"]["topics"] == topics

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr"
        assert headers["Content-Length"] == 331
        assert len(headers["CESR-ATTACHMENT"]) == 144
        assert headers["CESR-ATTACHMENT"] == (b'-CAj-YAiEChqfw9-5A5qMrZ8_YgOAJm8iKMbTAUvfDVVI6KNGL3M-'
                                              b'KAWAAA6IQQzemdSFuRZ3AU0jbL9qn9D__V6ygWoVIvrZEzujBmQwng-'
                                              b'_xDuIwxX599cuwuliEl4CfYzuynwVYdVqz0K')

        ims = bytearray(args["body"])
        ims.extend(headers["CESR-ATTACHMENT"])
        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, serder.said))
        assert cache is not None
        assert cache.mdt == serder.stamp
        assert cache.d == 1000

        msgs = hab.query(pre=hab.pre, src=wit, route="logs", query=dict(s=0),
                         version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        msgs.extend(hab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0))

        client = MockClient()
        streamCESRRequests(client, msgs, dest=wit)
        assert len(client.args) == 2
        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        serder = SerderKERI(raw=args["body"])
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.json
        assert serder.ked["t"] == Ilks.icp
        assert serder.ked["i"] == hab.pre

        headers = args["headers"]
        assert headers['Content-Type'] == 'application/cesr'
        assert headers['Content-Length'] == 301
        assert len(headers['CESR-ATTACHMENT']) == 92

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        serder = SerderKERI(raw=args["body"])
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.json
        assert serder.ked["t"] == Ilks.qry
        assert serder.ked["i"] == hab.pre
        assert serder.ked["r"] == "logs"
        assert serder.ked["q"]["s"] == 0
        assert serder.ked["q"]["i"] == hab.pre
        assert serder.ked["q"]["src"] == wit

        headers = args["headers"]
        assert headers['Content-Type'] == 'application/cesr'
        assert headers['Content-Length'] == len(args["body"])
        assert len(headers['CESR-ATTACHMENT']) == 144
        assert headers['CESR-ATTACHMENT'] == (b'-CAj-YAiEChqfw9-5A5qMrZ8_YgOAJm8iKMbTAUvfDVVI6KNGL3M-'
                                              b'KAWAACFNqIda6R-Q-cZa_bWrLwt7busxW5fKnqyTP_ToGnI7Chsjv'
                                              b'2TyFy-T52aVmemAXjZsxWrOrZtE8WcvU0b57EE')

        ims = bytearray(args["body"])
        ims.extend(headers["CESR-ATTACHMENT"])
        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, serder.said))
        assert cache is not None
        assert cache.mdt == serder.stamp
        assert cache.d == 1000


if __name__ == '__main__':
    test_parse_cesr_request()
