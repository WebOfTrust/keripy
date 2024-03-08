# -*- encoding: utf-8 -*-
"""
tests.peer.httping module

"""

import falcon
import pytest
from falcon.testing import helpers

from keri.app import habbing, httping
from keri.core import coring, serdering
from keri.vdr import credentialing, verifying


def test_parse_cesr_request():
    req = helpers.create_req()
    with pytest.raises(falcon.HTTPError):
        httping.parseCesrHttpRequest(req=req)

    req = helpers.create_req(headers=dict(
        Content_Type=httping.CESR_CONTENT_TYPE,
    ))
    with pytest.raises(falcon.HTTPError):
        httping.parseCesrHttpRequest(req=req)

    req = helpers.create_req(headers=dict(
        Content_Type=httping.CESR_CONTENT_TYPE,
        CESR_DATE_HEADER="2021-06-27T21:26:21.233257+00:00",
    ))
    with pytest.raises(falcon.HTTPError):
        httping.parseCesrHttpRequest(req=req)

    req = helpers.create_req(
        headers=dict(
            Content_Type=httping.CESR_CONTENT_TYPE,
            CESR_DATE="2021-06-27T21:26:21.233257+00:00",
        ),
        body='{}',
    )
    with pytest.raises(falcon.HTTPError):
        httping.parseCesrHttpRequest(req=req)

    req = helpers.create_req(
        path="/credential/issue",
        headers=dict(
            Content_Type=httping.CESR_CONTENT_TYPE,
            CESR_DATE="2021-06-27T21:26:21.233257+00:00",
            CESR_ATTACHMENT="-H000000000"
        ),
        body='{"i": 1234}',
    )

    cr = httping.parseCesrHttpRequest(req=req)
    assert cr.payload == dict(i=1234)
    assert cr.attachments == "-H000000000"


class MockClient:

    def __init__(self):
        self.args = []

    def request(self, **kwargs):
        self.args.append(kwargs)


def test_create_cesr_request(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef') as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test")

        verfer = verifying.Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        client = MockClient()

        httping.createCESRRequest(msg, client, dest=wit, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        serder = serdering.SerderKERI(raw=args['body'])
        assert serder.ked["t"] == coring.Ilks.qry
        assert serder.ked["r"] == "tels"

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 254
        assert len(headers["CESR-ATTACHMENT"]) == 144

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.createCESRRequest(msg, client, dest=wit, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"EPFXeGxCj6VtDCBxgV7HUGF0UxdP9fSZhQw3'
                                b'tWH2TFsY","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == bytearray(
            b'-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB6P97k'
            b'Z3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAz'
            b'qSTBmJzI8RvIezsJ')


def test_stream_cesr_request(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef') as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="test")

        verfer = verifying.Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        client = MockClient()

        httping.streamCESRRequests(client, msg, dest=wit, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        serder = serdering.SerderKERI(raw=args['body'])
        assert serder.ked["t"] == coring.Ilks.qry
        assert serder.ked["r"] == "tels"

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 254
        assert len(headers["CESR-ATTACHMENT"]) == 144

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.streamCESRRequests(client, msg, dest=wit, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"EPFXeGxCj6VtDCBxgV7HUGF0UxdP9fSZhQw3'
                                b'tWH2TFsY","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB6P97k'
                                              b'Z3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAz'
                                              b'qSTBmJzI8RvIezsJ')

        msgs = hab.query(pre=hab.pre, src=wit, route="logs", query=dict(s=0))
        msgs.extend(hab.makeOwnEvent(sn=0))

        client = MockClient()
        httping.streamCESRRequests(client, msgs, dest=wit)
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
        assert headers['Content-Type'] == 'application/cesr+json'
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
        assert headers['Content-Type'] == 'application/cesr+json'
        assert headers['CESR-ATTACHMENT'] == (b'-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAA9IV9O'
                                              b'7nlInObE0V8E6xphJcv9u_53mP7YFOzESF3RsZOyN_LguuC-ZBBxY_-yjlh-YKeX'
                                              b'jIu5ZwJILbL2bcID')


if __name__ == '__main__':
    test_parse_cesr_request()
