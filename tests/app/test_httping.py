# -*- encoding: utf-8 -*-
"""
tests.peer.httping module

"""

import falcon
import pytest
from falcon.testing import helpers

from keri.app import habbing, httping
from keri.vdr import issuing, verifying


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
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        client = MockClient()

        httping.createCESRRequest(msg, client, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        assert args["body"] == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"Efp5Surn_KGO6S4G6ZnExhK83kCEIpVQA3Qi'
                                b'hDyeHG-Y","dt":"2021-01-01T00:00:00.000000+00:00","r":"tels","rr":"","q":{"i'
                                b'":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4","ri":"ERAY2VjFALVZAAuC3GDM-'
                                b'36qKD8ZhUaKF55MWtITBFnc"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 254
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAAfmxUPk'
                                              b'uSzu50ixd9C5NwXzI7Dm2IdtD_PKExpzz0CQRwa9d3fvuWG-iQKiPxPCMCDEOmDw'
                                              b'x9iBO55UL94q0CAQ')

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.createCESRRequest(msg, client, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"ElYIm5ib2SdXRXtoby1-M0BQtA5qTlKE8U7s'
                                b'-hVSDUDA","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAAdeUIE6'
                                              b'CCnL2MWdEHoq-JHvq2wKxinMWQ1a2MTvs6DfPUgqd4heSESuQb1zkkE-EUZZuHIP'
                                              b'_UVaaDKnb9X5oBBw')


def test_stream_cesr_request(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        wit = "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hby=hby)
        msg = verfer.query(hab.pre, issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        client = MockClient()

        httping.streamCESRRequests(client, msg, path="/qry/tels")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/tels"
        assert args["body"] == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"Efp5Surn_KGO6S4G6ZnExhK83kCEIpVQA3Qi'
                                b'hDyeHG-Y","dt":"2021-01-01T00:00:00.000000+00:00","r":"tels","rr":"","q":{"i'
                                b'":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4","ri":"ERAY2VjFALVZAAuC3GDM-'
                                b'36qKD8ZhUaKF55MWtITBFnc"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 254
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAAfmxUPk'
                                              b'uSzu50ixd9C5NwXzI7Dm2IdtD_PKExpzz0CQRwa9d3fvuWG-iQKiPxPCMCDEOmDw'
                                              b'x9iBO55UL94q0CAQ')

        msg = hab.query(pre=hab.pre, src=wit, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.streamCESRRequests(client, msg, path="/qry/mbx")

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/qry/mbx"
        assert args["body"] == (b'{"v":"KERI10JSON000104_","t":"qry","d":"ElYIm5ib2SdXRXtoby1-M0BQtA5qTlKE8U7s'
                                b'-hVSDUDA","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                b':0,"i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","src":"BGKVzj4ve0VSd8z'
                                b'_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')

        headers = args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 260
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAAdeUIE6'
                                              b'CCnL2MWdEHoq-JHvq2wKxinMWQ1a2MTvs6DfPUgqd4heSESuQb1zkkE-EUZZuHIP'
                                              b'_UVaaDKnb9X5oBBw')

        msgs = hab.query(pre=hab.pre, src=wit, route="logs", query=dict(s=0))
        msgs.extend(hab.makeOwnEvent(sn=0))

        client = MockClient()
        httping.streamCESRRequests(client, msgs)
        assert len(client.args) == 2
        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        assert args["body"] == (b'{"v":"KERI10JSON000120_","t":"icp","d":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc"'
                                b',"i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","s":"0","kt":"1","k":["DaYh8uaASu'
                                b'DjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg"],"n":"EZij_Yc1y_3EWLq9hFcHHGBarphq0pX1dIkPw1OHYS6'
                                b'k","bt":"0","b":[],"c":[],"a":[]}')
        headers = args["headers"]
        assert headers['Content-Length'] == 288
        assert headers['Content-Type'] == 'application/cesr+json'
        assert headers['CESR-ATTACHMENT'] == (b'-AABAAa3Md92hkKoYXIvNCUTQR_X6tx1r4fvqcbbGxx-XtJBI7KFKe5H34dyhz229K18H0T'
                                              b'6eNtyocNu1Lof0V_vkIAA')

        args = client.args.pop()
        assert args["method"] == "POST"
        assert args["path"] == "/"

        assert args["body"] == (b'{"v":"KERI10JSON000105_","t":"qry","d":"EaWkBhJHu8GoqU6fSRtY1kHYMuL3DQM1ZE4n'
                                b'Jr4yuATc","dt":"2021-01-01T00:00:00.000000+00:00","r":"logs","rr":"","q":{"s'
                                b'":0,"i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","src":"BGKVzj4ve0VSd8'
                                b'z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}')
        headers = args["headers"]
        assert headers['Content-Length'] == 261
        assert headers['Content-Type'] == 'application/cesr+json'
        assert headers['CESR-ATTACHMENT'] == (b'-VAj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAAqKSqAb'
                                              b'nP_68sXvxmeFmsSVtZemIR9x2bu2nlzHldsDAjRY6MMbLIgu7cpuZILgMjbGeWx0'
                                              b'oBBbBNmnCtoh6AAA')


if __name__ == '__main__':
    test_parse_cesr_request()
