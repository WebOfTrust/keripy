# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json

import falcon
from falcon import testing

from ..app import test_grouping
from keri.app import habbing, agenting, storing, grouping
from keri.core import coring
from keri.vc import proving
from keri.vdr import viring, issuing, verifying


def test_credential_handlers(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True) as hab, \
            habbing.openHab(name="recp", transferable=True) as recp:
        app = falcon.App()

        reger = viring.Registry(name=hab.name, temp=True)
        verifier = verifying.Verifier(hab=hab, name="verifier", reger=reger)
        issuer = issuing.Issuer(hab=hab, name=hab.name, reger=reger, noBackers=True)

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        assert cue["kin"] == "kevt"
        cue = issuer.cues.popleft()
        assert cue["kin"] == "send"

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hab=hab)

        kiwi = agenting.KiwiServer(hab=hab,
                                   rep=repd,
                                   verifier=verifier,
                                   issuers=issuers,
                                   app=app,
                                   controller="",
                                   insecure=True)

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

        tevt = (
            b'{"v":"KERI10JSON0000ba_","i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0","s":"0","t":"iss",'
            b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38",'
            b'"dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAgEh57w4eMiFg8hy8gZmA'
            b'-FnLWIgQzDcC2OMmpiyCUZz_k')
        kevt = (
            b'{"v":"KERI10JSON000107_","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","s":"2","t":"ixn",'
            b'"p":"ET6FzE7z8CFUDyfKjq__QIln5RwHBJrJz5amM9XYukLc",'
            b'"a":[{"i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0","s":"0",'
            b'"d":"EnfAA4Gqw05dzKCdbfH2D13_FRYKg-sJw1dzH1oW6EM8"}]}-AABAAko7tF62BU4AhJgksyo'
            b'-H4GeQH7KvxN7qZMxQvYNXRXUqc2UvEeI39cfCfi-_FYCmXf9j5oh1uSspEE7B8iYxDg')
        cred = (
            b'{"v":"KERI10JSON0001ff_","i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0",'
            b'"x":"E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4","ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"d":{"i":"EW16NAGaPl2EwitjEnNKzYci5pqljuP7wXeuHMm72m_U","type":["VerifiableCredential",'
            b'"vLEIGLEIFCredential"],"si":"EgGTr6JW6geC7wlSIz6qPsYz8a-ITy52o3urlh0F2MLE",'
            b'"dt":"2021-01-01T00:00:00.000000+00:00","LEI":"1234567890abcdefg"},'
            b'"s":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38"}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
            b'-AABAAqyIShWPH1LrXJ32DOvm0gcTxneTAvOPTDHtIPscVslopfheKbrXKBLeYtdgOVj8TTffxB-bWnnxwYYbPcp40AA')

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == kevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == tevt

        creder = proving.Credentialer(raw=cred)
        assert reger.creds.get(creder.saider.qb64b).raw == creder.raw

        result = client.simulate_post(path="/credential/revoke",
                                      body=b'{"registry": "E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38", "said": '
                                           b'"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0"}')
        assert result.status == falcon.HTTP_202

        rev = (
            b'{"v":"KERI10JSON0000ed_","i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0","s":"1","t":"rev",'
            b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38","p":"EnfAA4Gqw05dzKCdbfH2D13_FRYKg-sJw1dzH1oW6EM8",'
            b'"dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEojtwjysa0rQw'
            b'-bP1FIPqSvCnrclFSyuzI4NLQ0MimJY')
        rkevt = (
            b'{"v":"KERI10JSON000107_","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","s":"3","t":"ixn",'
            b'"p":"Eh57w4eMiFg8hy8gZmA-FnLWIgQzDcC2OMmpiyCUZz_k",'
            b'"a":[{"i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0","s":"1",'
            b'"d":"EtmnkuN7O2lZKeD-Setw_4XcWqc-_LP55yT0QkMQ23wo"}]}-AABAAt7jWpQkBYrMX6k'
            b'-XpcPxtLdwuUgpbxg45zoDLJKLs1y3tm7PlBgDBiMR15YCUK-g3nST59cGr0FRwRUn0RXcBQ')
        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == rkevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == rev


def test_credential_handlers_singlesig(mockHelpingNowUTC):
    with test_grouping.openMutlsig(prefix="test") as (hab1, hab2, hab3), \
            habbing.openHab(name="recp", transferable=True) as recp:
        app = falcon.App()

        reger = viring.Registry(name=hab1.name, temp=True)
        verifier = verifying.Verifier(hab=hab1, name="verifier", reger=reger)
        issuer = issuing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hab=hab1)

        kiwi = agenting.KiwiServer(hab=hab1,
                                   rep=repd,
                                   verifier=verifier,
                                   issuers=issuers,
                                   app=app,
                                   controller="",
                                   insecure=True)

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
            registry="test",
            schema=schema,
            recipient=recp.pre,
            type="vLEIGLEIFCredential",
            credentialData=data
        )
        b = json.dumps(body).encode("utf-8")
        result = client.simulate_post(path="/credential/issue", body=b)
        assert result.status == falcon.HTTP_200

        cred = (
            b'{"v":"KERI10JSON0001ff_","i":"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0",'
            b'"x":"E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4","ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"d":{"i":"EW16NAGaPl2EwitjEnNKzYci5pqljuP7wXeuHMm72m_U","type":["VerifiableCredential",'
            b'"vLEIGLEIFCredential"],"si":"EgGTr6JW6geC7wlSIz6qPsYz8a-ITy52o3urlh0F2MLE",'
            b'"dt":"2021-01-01T00:00:00.000000+00:00","LEI":"1234567890abcdefg"},'
            b'"s":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38"}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
            b'-AABAAqyIShWPH1LrXJ32DOvm0gcTxneTAvOPTDHtIPscVslopfheKbrXKBLeYtdgOVj8TTffxB-bWnnxwYYbPcp40AA')

        assert len(issuer.cues) == 1

        cue = issuer.cues.popleft()
        assert cue["kin"] == "multisig"
        assert cue["op"] == grouping.Ops.ixn
        assert cue["data"] == [dict(
            i="EY6abBtd60qGCttqOSOW27w_DZhi9U1p2K6RV0G4wqiE",
            s="0",
            d="EwUyilaYsfLo7zFqXFnp1T9nvsbd2b1IAaCW-i9LFQyo"
        )]

        result = client.simulate_post(path="/credential/revoke",
                                      body=b'{"registry": "E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38", "said": '
                                           b'"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0"}')
        assert result.status == falcon.HTTP_CONFLICT
        assert result.text == ("Invalid revoke of EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0 that has not been "
                               "issued pre=E-b2o4iuCAD2D68XAYxA3L8vqWJ1pxAXyxRSL95CiGS0.")


def test_issue_credential_full_multisig():
    with test_grouping.openMutlsig(prefix="test") as (hab1, hab2, hab3), \
            habbing.openHab(name="recp", transferable=True) as recp:
        # Verify the group identifier was incepted properly and matches the identifiers
        assert hab1.pre == "ELQoqCOdxWcd3zhQTW7io5XJYAJLmhpbY8YqQF0sxZLo"
        assert hab2.pre == "EH-i-vxKSbaJQtal3V_ltrtjs7O1nuCHn4iqxdvdGOj0"
        assert hab3.pre == "EuK3T40uWRDXGZF9YApOjoTkLeDjjr7UPUqfCp5B04Fo"

        gid = "EbRGD66vYtbohJwGh-B2uPwHUDH3WrLcc_1Gn1ksSEu0"
        group1 = hab1.db.gids.get(hab1.pre)
        assert group1.gid == gid
        assert group1.lid == hab1.pre
        group2 = hab2.db.gids.get(hab2.pre)
        assert group2.gid == gid
        assert group2.lid == hab2.pre
        group3 = hab3.db.gids.get(hab3.pre)
        assert group3.gid == gid
        assert group3.lid == hab3.pre

        # Now create the Falcon app and the Kiwi Server
        # with one of the Group participants Habitats
        app = falcon.App()

        reger = viring.Registry(name=hab1.name, temp=True)
        verifier = verifying.Verifier(hab=hab1, name="verifier", reger=reger)
        issuer = issuing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)

        assert len(issuer.cues) == 1
        cue = issuer.cues.popleft()
        assert cue["kin"] == "multisig"
        assert cue["data"] == [dict(
            i='EY6abBtd60qGCttqOSOW27w_DZhi9U1p2K6RV0G4wqiE',
            s='0',
            d='EwUyilaYsfLo7zFqXFnp1T9nvsbd2b1IAaCW-i9LFQyo'
        )]

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hab=hab1)

        kiwi = agenting.KiwiServer(hab=hab1,
                                   rep=repd,
                                   verifier=verifier,
                                   issuers=issuers,
                                   app=app,
                                   controller="",
                                   insecure=True)
        assert kiwi is not None

        # Create the credential to be issued
        schema = "E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            registry=issuer.regk,
            schema=schema,
            source=hab1.pre,
            recipient=recp.pre,
            type="vLEIGLEIFCredential",
            credentialData=data
        )
        b = json.dumps(body).encode("utf-8")

        # Use Falcon test all to submit the request to issue a credential
        client = testing.TestClient(app)
        result = client.simulate_post(path="/credential/issue", body=b)
        assert result.status == falcon.HTTP_200

        creder = proving.Credentialer(crd=result.json, kind=coring.Serials.json)
        print(creder.pretty())

        # The Issuer will have cue'd up a multisig request to be processed
        assert len(issuer.cues) == 1
        cue = issuer.cues.popleft()

        assert cue["kin"] == "multisig"
        data = cue["data"]
        assert len(data) == 1
        print(data[0])
        assert data[0]['s'] == '0'
        assert data[0]['i'] == creder.saider.qb64
        assert 'd' in data[0]
