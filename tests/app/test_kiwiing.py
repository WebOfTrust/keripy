# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""

import json

import falcon
from falcon import testing

from keri.app import (habbing, kiwiing, booting, notifying)
from keri.core import coring
from keri.vdr import credentialing


def test_aied_ends():
    bran = "1B88Kq7afAZHlxsNIBE5y"
    with habbing.openHby(name="test", salt=coring.Salter(raw=b'0123456789abcdef').qb64, bran=bran) as hby:
        app = falcon.App()
        notifier = notifying.Notifier(hby=hby)
        regery = credentialing.Regery(hby=hby, name="test", temp=True)
        _ = kiwiing.loadEnds(hby=hby,
                             rgy=regery,
                             verifier=None,
                             notifier=notifier,
                             signaler=notifier.signaler,
                             app=app, path="/",
                             registrar=None,
                             credentialer=None,
                             servery=booting.Servery(port=1234),
                             bootConfig=dict(),
                             counselor=None)
        client = testing.TestClient(app)

        response = client.simulate_get("/codes")
        assert response.status == falcon.HTTP_200
        assert "passcode" in response.json
        aeid = response.json["passcode"]
        assert len(aeid) == booting.DEFAULT_PASSCODE_SIZE

        #  Change passcode
        nbran = "pouh228IgK9RhloUnkydZ"
        body = dict(current=bran, passcode=nbran)
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_202

        # Try to use the old passcode again
        body = dict(current=bran, passcode=nbran)
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_401

        # Change back to the original passcode
        body = dict(current=nbran, passcode=bran)
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_202

        # Try to use an invalid passcode
        body = dict(current=bran, passcode="ABCDEF")
        response = client.simulate_post("/codes", body=json.dumps(body).encode("utf-8"))
        assert response.status == falcon.HTTP_400


if __name__ == "__main__":
    test_aied_ends()
