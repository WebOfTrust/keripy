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
    with habbing.openHab(name="test", transferable=True, temp=True) as hab:
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hab=hab)
        msg = verfer.query(issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           res="tels")
        client = MockClient()

        httping.createCESRRequest(msg, client, date="2021-02-13T19:16:50.750302+00:00")

        assert client.args["method"] == "POST"
        assert client.args["path"] == "/qry/tels"
        assert client.args["body"] == (b'{"v":"KERI10JSON0000cb_","t":"qry","dt":"2021-01-01T00:00:00.000000+00:00","'
                                       b'r":"tels","rr":"","q":{"i":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4","r'
                                       b'i":"EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78Tt2r9M4"}}')

        q = client.args["qargs"]
        assert q == dict(i='Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4',
                         ri='EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78Tt2r9M4')

        headers = client.args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 203
        assert headers["CESR-DATE"] == "2021-02-13T19:16:50.750302+00:00"
        assert headers["CESR-ATTACHMENT"] == (b'-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E-AABAA4WmPtNJALt'
                                              b'6f4Xn-HnsPrfplKgAeyxQIxsYm9T-rTNFIpdyOnxynA0wgcEJ_FOcTo9R0krY25t'
                                              b'QvpBOzfT0aDA')

        msg = hab.query(pre=hab.pre, route="mbx", query=dict(s=0))
        client = MockClient()

        httping.createCESRRequest(msg, client, date="2021-02-13T19:16:50.750302+00:00")

        assert client.args["method"] == "POST"
        assert client.args["path"] == "/qry/mbx"
        assert client.args["body"] == (b'{"v":"KERI10JSON00009c_","t":"qry","dt":"2021-01-01T00:00:00.000000+00:00","'
                                       b'r":"mbx","rr":"","q":{"s":0,"i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9'
                                       b'E"}}')

        headers = client.args["headers"]
        assert headers["Content-Type"] == "application/cesr+json"
        assert headers["Content-Length"] == 156
        assert headers["CESR-DATE"] == "2021-02-13T19:16:50.750302+00:00"
        assert headers["CESR-ATTACHMENT"] == (b'-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E-AABAAMX88afPpEf'
                                              b'F_HF-E-1uZKyv8b_TdILi2x8vC3Yi7Q7yzHn2fR6Bkl2yn-ZxPqmsTfV3f-H_VQw'
                                              b'Mgk7jYEukVCA')


if __name__ == '__main__':
    test_parse_cesr_request()
