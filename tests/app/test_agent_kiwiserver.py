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

        schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            registry=issuer.regk,
            schema=schema,
            recipient=recp.pre,
            type="GLEIFvLEICredential",
            credentialData=data
        )
        b = json.dumps(body).encode("utf-8")
        result = client.simulate_post(path="/credential/issue", body=b)
        assert result.status == falcon.HTTP_200

        tevt = (
            b'{"v":"KERI10JSON0000ba_","i":"Eoi8WwQ0EQJ7TDpysGFVO6JBMONAbgoFNa'
            b'qXXjJYulW8","s":"0","t":"iss","ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15'
            b'PEcJ7f9ejHjJMC38","dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0A'
            b'AAAAAAAAAAAAAAAAAAAAAgEz9MG5UtqItcTyGHurKAdWodVv71L9fzx32OAKrB4Lts')
        kevt = (
            b'{"v":"KERI10JSON000107_","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7'
            b'pEE-YfcI9E","s":"2","t":"ixn","p":"ET6FzE7z8CFUDyfKjq__QIln5RwHB'
            b'JrJz5amM9XYukLc","a":[{"i":"Eoi8WwQ0EQJ7TDpysGFVO6JBMONAbgoFNaqX'
            b'XjJYulW8","s":"0","d":"EDkZCcOySbAPMfXC-d6aSkyv4uV7zFyxAMhMwCbr5'
            b'RUg"}]}-AABAA4RZ3h8hzbTQ_70xofGN3mPMSuaUVvlqlA2a2RSfTny7GcA3MsDP'
            b'r5nF6yppe4Ajj3oZM24WX0TqlIfVHAMaYCA')
        cred = (
            b'{"v":"KERI10JSON0001ce_","d":"Eoi8WwQ0EQJ7TDpysGFVO6JBMONAbgoFNaqXXjJYulW8",'
            b'"s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"a":{"d":"EBDdZ9LiUoY4mwNaswmiNYnbpi8ZMAtn5_37mKBZOiL4",'
            b'"i":"EgGTr6JW6geC7wlSIz6qPsYz8a-ITy52o3urlh0F2MLE","dt":"2021-01-01T00:00:00.000000+00:00",'
            b'"t":["VerifiableCredential","GLEIFvLEICredential"],"LEI":"1234567890abcdefg",'
            b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38"},"p":[]}')

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == kevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == tevt

        creder = proving.Credentialer(raw=cred)
        assert reger.creds.get(creder.saider.qb64b).raw == creder.raw

        # Try to revoke a credential that doesn't exist and get the appropriate error
        result = client.simulate_post(path="/credential/revoke",
                                      body=b'{"registry": "E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38", "said": '
                                           b'"EhFUqi_LAldgF0I6XmN9JGjc7Wh7ld1yCRiUxtMDVvow"}')
        assert result.status == falcon.HTTP_409

        # Now revoke the actual credential
        result = client.simulate_post(path="/credential/revoke",
                                      body=b'{"registry": "E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38", "said": '
                                           b'"Eoi8WwQ0EQJ7TDpysGFVO6JBMONAbgoFNaqXXjJYulW8"}')
        assert result.status == falcon.HTTP_202

        rev = (
            b'{"v":"KERI10JSON0000ed_","i":"Eoi8WwQ0EQJ7TDpysGFVO6JBMONAbgoFNa'
            b'qXXjJYulW8","s":"1","t":"rev","ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15'
            b'PEcJ7f9ejHjJMC38","p":"EDkZCcOySbAPMfXC-d6aSkyv4uV7zFyxAMhMwCbr5'
            b'RUg","dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAA'
            b'AAAAAAAAwExysv80VRWFIfGEBFmcCjEOs8SGeZ9Rx8-NuK2F9FyWc')
        rkevt = (
            b'{"v":"KERI10JSON000107_","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7'
            b'pEE-YfcI9E","s":"3","t":"ixn","p":"Ez9MG5UtqItcTyGHurKAdWodVv71L'
            b'9fzx32OAKrB4Lts","a":[{"i":"Eoi8WwQ0EQJ7TDpysGFVO6JBMONAbgoFNaqX'
            b'XjJYulW8","s":"1","d":"EoSOeEKX0h3JIUHRWtQuX3ajKWbTHaXXRfcgsXCOl'
            b'x8I"}]}-AABAA8xSLe89nS_jf4H4bJa8xhP5CFWDvQgbGA_JLLUYI7-EErjxUuCv'
            b'c-n8AuT1DPnjRiSRg0mTkXOS0cK0eHxPEDg')
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

        schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            registry="test",
            schema=schema,
            recipient=recp.pre,
            type="GLEIFvLEICredential",
            credentialData=data
        )
        b = json.dumps(body).encode("utf-8")
        result = client.simulate_post(path="/credential/issue", body=b)
        assert result.status == falcon.HTTP_200
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
        schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            registry=issuer.regk,
            schema=schema,
            source=hab1.pre,
            recipient=recp.pre,
            type="GLEIFvLEICredential",
            credentialData=data
        )
        b = json.dumps(body).encode("utf-8")

        # Use Falcon test all to submit the request to issue a credential
        client = testing.TestClient(app)
        result = client.simulate_post(path="/credential/issue", body=b)
        assert result.status == falcon.HTTP_200

        creder = proving.Credentialer(crd=result.json, kind=coring.Serials.json)

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
