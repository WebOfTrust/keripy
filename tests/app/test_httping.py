# -*- encoding: utf-8 -*-
"""
tests.peer.httping module

"""

import falcon
import pytest
from falcon.testing import helpers

from keri.app import habbing, httping
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
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = credentialing.Regery(hby=hby, name="test")
        issuer = regery.makeRegistry(prefix=hab.pre, name="test")

        verfer = verifying.Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        client = MockClient()

        httping.createCESRRequest(msg, client, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        assert args["body"] == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"EXOG6T6nt1BABGbD1OtypQe6SjZAAsrnHFZY'
                                b'wkCneA1k","dt":"2021-01-01T00:00:00.000000+00:00","r":"tels","rr":"","q":{"i'
                                b'":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4","ri":"EjPXk1a_MtWR3a0qrZiJ3'
                                b'4c971FxiHyCZSRo6482KPDs"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 254
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAuArHNO'
                                              b'Mt9SxHkUhHh8-f27XpHDe8lMVAiYPqvbynY2xc_XbvgTWsPn4VAOO-0nuOGVCzwW'
                                              b'zCsVOyc8LLiOF-Ag')

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.createCESRRequest(msg, client, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"E1Xdkk3WlmV03aL7R63u5z-VmQzvrRjwXpwC'
                                b'xrkkMlxg","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAuewE0c'
                                              b'fWF-X9-gcw_XEf5k1NupFKUBUsRxPYs3kNU4pe8lW45GN7SryfCtXcpcmwnCeudJ'
                                              b'3w32sUULzp2CUoCg')


def test_stream_cesr_request(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        regery = credentialing.Regery(hby=hby, name="test")
        issuer = regery.makeRegistry(prefix=hab.pre, name="test")

        verfer = verifying.Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        client = MockClient()

        httping.streamCESRRequests(client, msg, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        assert args["body"] == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"EXOG6T6nt1BABGbD1OtypQe6SjZAAsrnHFZY'
                                b'wkCneA1k","dt":"2021-01-01T00:00:00.000000+00:00","r":"tels","rr":"","q":{"i'
                                b'":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4","ri":"EjPXk1a_MtWR3a0qrZiJ3'
                                b'4c971FxiHyCZSRo6482KPDs"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 254
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAuArHNO'
                                              b'Mt9SxHkUhHh8-f27XpHDe8lMVAiYPqvbynY2xc_XbvgTWsPn4VAOO-0nuOGVCzwW'
                                              b'zCsVOyc8LLiOF-Ag')

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.streamCESRRequests(client, msg, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"E1Xdkk3WlmV03aL7R63u5z-VmQzvrRjwXpwC'
                                b'xrkkMlxg","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAuewE0c'
                                              b'fWF-X9-gcw_XEf5k1NupFKUBUsRxPYs3kNU4pe8lW45GN7SryfCtXcpcmwnCeudJ'
                                              b'3w32sUULzp2CUoCg')

        msgs = hab.query(pre=hab.pre, src=wit, route="logs", query=dict(s=0))
        msgs.extend(hab.makeOwnEvent(sn=0))

        client = MockClient()
        httping.streamCESRRequests(client, msgs)
        assert len(client.args) == 2
        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        assert args["body"] == (b'{"v":"KERI10JSON00012b_","t":"icp","d":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDp'
                                b'BGF9Z1Pc","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","s":"0","kt":"1'
                                b'","k":["DaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg"],"nt":"1","n":["EsBMmy'
                                b'evdbrDojd73T6UmBvSktf7f-i-Yu0LjsuRr7y4"],"bt":"0","b":[],"c":[],"a":[]}')
        headers = args["headers"]
        assert headers['Content-Length'] == 299
        assert headers['Content-Type'] == 'application/cesr+json'
        assert headers['CESR-ATTACHMENT'] == (b'-AABAAzyLnzgjNDU2AqLilXI1HlfIwdEoJzHErxbPv28asokuHZnTK3k_hBYH9tu'
                                              b'FRlUtE7AP1zX1bhm5GLnSVDu6vCw')

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        assert args["body"] == (b'{"v":"KERI10JSON000105_","t":"qry","d":"EStGzLcodkqvmwvbmmPKbMEOanrqsvko-4WT'
                                b'fD8G_QZ4","dt":"2021-01-01T00:00:00.000000+00:00","r":"logs","rr":"","q":{"s'
                                b'":0,"i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","src":"BGKVzj4ve0VSd8'
                                b'z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')
        headers = args["headers"]
        assert headers['Content-Length'] == 261
        assert headers['Content-Type'] == 'application/cesr+json'
        assert headers['CESR-ATTACHMENT'] == (b'-VAj-HABECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAA6Hyou7'
                                              b'rOsNZQ2hs-zPfHLJmLIQni-CDpILSYFjy25XgQ_dRe8b3n7LEv7lgr2r4fFoNB4l'
                                              b'EMeS0Jtlu-jargBw')


if __name__ == '__main__':
    test_parse_cesr_request()
