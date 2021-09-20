# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json

import falcon
from falcon import testing

from keri.app import habbing, agenting, storing
from keri.core import coring
from keri.vdr import viring, issuing


def test_credential_handlers(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True) as hab, \
            habbing.openHab(name="recp", transferable=True) as recp:
        app = falcon.App()

        reger = viring.Registry(name=hab.name, temp=True)
        issuer = issuing.Issuer(hab=hab, name=hab.name, reger=reger, noBackers=True)

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hab=hab)
        kiwi = agenting.KiwiServer(hab=hab, rep=repd, issuers=issuers, app=app, controller="", insecure=True)

        client = testing.TestClient(app)

        result = client.simulate_post(path="/registry/incept", body=b'{"name": "test"}')
        assert result.status == falcon.HTTP_202

        assert len(kiwi.registryIcpr.msgs) == 1
        msg = kiwi.registryIcpr.msgs.popleft()
        assert msg == dict(name="test")

        schema = "E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            registry=issuer.regk,
            schema=schema,
            source=hab.pre,
            recipient=recp.pre,
            type="vLEIGLEIFCredential",
            credentialData=data
        )
        b = json.dumps(body).encode("utf-8")
        result = client.simulate_post(path="/credential/issue", body=b)
        assert result.status == falcon.HTTP_200
        assert len(kiwi.tevts) == 1
        tevt = kiwi.tevts.popleft()

        assert tevt == bytearray(
            b'{"v":"KERI10JSON0000ba_","i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0","s":"0","t":"iss",'
            b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38",'
            b'"dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAgEh57w4eMiFg8hy8gZmA'
            b'-FnLWIgQzDcC2OMmpiyCUZz_k')

        assert len(kiwi.kevts) == 1
        kevt = kiwi.kevts.popleft()
        assert kevt == bytearray(
            b'{"v":"KERI10JSON000107_","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","s":"2","t":"ixn",'
            b'"p":"ET6FzE7z8CFUDyfKjq__QIln5RwHBJrJz5amM9XYukLc",'
            b'"a":[{"i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0","s":"0",'
            b'"d":"EnfAA4Gqw05dzKCdbfH2D13_FRYKg-sJw1dzH1oW6EM8"}]}-AABAAko7tF62BU4AhJgksyo'
            b'-H4GeQH7KvxN7qZMxQvYNXRXUqc2UvEeI39cfCfi-_FYCmXf9j5oh1uSspEE7B8iYxDg')

        cred = b'{"v": "KERI10JSON0001ff_", "i": "EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0", ' \
               b'"x": "E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4", ' \
               b'"ti": "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E", "d": {"i": ' \
               b'"EW16NAGaPl2EwitjEnNKzYci5pqljuP7wXeuHMm72m_U", "type": ["VerifiableCredential", ' \
               b'"vLEIGLEIFCredential"], "si": "EgGTr6JW6geC7wlSIz6qPsYz8a-ITy52o3urlh0F2MLE", ' \
               b'"dt": "2021-01-01T00:00:00.000000+00:00", "LEI": "1234567890abcdefg"}, ' \
               b'"s": "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E", ' \
               b'"ri": "E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38"}'

        assert len(kiwi.rep.reps) == 1
        msg = kiwi.rep.reps.popleft()
        assert msg["dest"] == recp.pre
        assert msg["topic"] == "credential"
        exn = msg["rep"]
        assert exn.ked["t"] == coring.Ilks.exn
        assert exn.ked['r'] == '/credential/issue'
        d = exn.ked['d']
        vc = d['vc'][0]['vc']

        assert (json.dumps(vc).encode("utf-8")) == cred
        assert (json.dumps(result.json).encode("utf-8")) == cred



