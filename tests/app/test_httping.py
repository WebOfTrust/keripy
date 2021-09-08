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


def test_create_cesr_request():
    with habbing.openHab(name="test", transferable=True, temp=True) as hab:
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hab=hab)
        msg = verfer.query(issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           res="tels")
        client = MockClient()

        httping.createCESRRequest(msg, client, date="2021-02-13T19:16:50.750302+00:00")

        assert client.args["method"] == "POST"
        assert client.args["path"] == "/req/tels"
        assert client.args["body"] == (
            b'{"v":"KERI10JSON00009b_","t":"req","r":"tels","q":{"i":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",'
            b'"ri":"EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78Tt2r9M4"}}')
        q = client.args["qargs"]
        assert q == dict(i='Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4',
                         ri='EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78Tt2r9M4')

        headers = client.args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 155
        assert headers["CESR-DATE"] == "2021-02-13T19:16:50.750302+00:00"
        assert headers["CESR-ATTACHMENT"] == bytearray(
            b'-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E'
            b'-AABAAhulhMW2RDUCHK5mxHryjlQ0i3HW_6CXbAGjNnHb9U9pq6N0C9DiavUbX6SgDskKIfoQLtV_EqTI_q9AyNAstAQ')

        msg = hab.query(pre=hab.pre, res="mbx", query=dict(s=0))
        client = MockClient()

        httping.createCESRRequest(msg, client, date="2021-02-13T19:16:50.750302+00:00")

        assert client.args["method"] == "POST"
        assert client.args["path"] == "/req/mbx"
        assert client.args["body"] == (b'{"v":"KERI10JSON00006c_","t":"req","r":"mbx","q":{"s":0,"i":"E4YPqsEOaPNaZxV'
                                       b'IbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"}}')

        headers = client.args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 108
        assert headers["CESR-DATE"] == "2021-02-13T19:16:50.750302+00:00"
        assert headers["CESR-ATTACHMENT"] == bytearray(
            b'-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E-AABAAh4UoPxFt3F'
            b'uRenCfSFJYlygq92oYqiGanAmzJ6EqHGXM-Y9byNsuhiaBTsl3V5th657-zeK1jG'
            b'vcmRxFnTdiAg')


if __name__ == '__main__':
    test_parse_cesr_request()
