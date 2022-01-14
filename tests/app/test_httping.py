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
    assert cr.resource == "/credential/issue"
    assert cr.date == "2021-06-27T21:26:21.233257+00:00"
    assert cr.payload == dict(i=1234)
    assert cr.attachments == "-H000000000"


class MockClient:

    def __init__(self):
        self.args = dict()

    def request(self, **kwargs):
        self.args = kwargs


def test_create_cesr_request(mockHelpingNowUTC):
    with habbing.openHabitat(name="test", transferable=True, temp=True) as hab:
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hab=hab)
        msg = verfer.query(issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           route="tels")
        client = MockClient()

        httping.createCESRRequest(msg, client, date="2021-02-13T19:16:50.750302+00:00")

        assert client.args["method"] == "POST"
        assert client.args["path"] == "/qry/tels"
        assert client.args["body"] == (b'{"v":"KERI10JSON0000fe_","t":"qry","d":"Efp5Surn_KGO6S4G6ZnExhK83kCEIpVQA3Qi'
                                       b'hDyeHG-Y","dt":"2021-01-01T00:00:00.000000+00:00","r":"tels","rr":"","q":{"i'
                                       b'":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4","ri":"ERAY2VjFALVZAAuC3GDM-'
                                       b'36qKD8ZhUaKF55MWtITBFnc"}}')

        q = client.args["qargs"]
        assert q == {'i': 'Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4',
                     'ri': 'ERAY2VjFALVZAAuC3GDM-36qKD8ZhUaKF55MWtITBFnc'}

        headers = client.args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 254
        assert headers["CESR-DATE"] == "2021-02-13T19:16:50.750302+00:00"
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAAfmxUPk'
                                              b'uSzu50ixd9C5NwXzI7Dm2IdtD_PKExpzz0CQRwa9d3fvuWG-iQKiPxPCMCDEOmDw'
                                              b'x9iBO55UL94q0CAQ')

        msg = hab.query(pre=hab.pre, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.createCESRRequest(msg, client, date="2021-02-13T19:16:50.750302+00:00")

        assert client.args["method"] == "POST"
        assert client.args["path"] == "/qry/mbx"
        assert client.args["body"] == (b'{"v":"KERI10JSON0000cf_","t":"qry","d":"EpYeo95qxKGAtIdCeOYEaSmKSLl0Tgs9s31o'
                                       b'i1sdQBHs","dt":"2021-01-01T00:00:00.000000+00:00","r":"mbx","rr":"","q":{"s"'
                                       b':0,"i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc"}}')

        headers = client.args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 207
        assert headers["CESR-DATE"] == "2021-02-13T19:16:50.750302+00:00"
        assert headers["CESR-ATTACHMENT"] == (b'-VAj-HABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAA0ThN4-'
                                              b'h1mJSFkI6H5e_Z4We_VE44MeV8gBWmI-pw-CS8HZ0947Z6h_1hmwrvTfR16HlxWu'
                                              b'wK_i8NA-cxdg45Bg')


if __name__ == '__main__':
    test_parse_cesr_request()
