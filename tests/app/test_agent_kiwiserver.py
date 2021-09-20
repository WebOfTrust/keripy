# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json

import falcon
from falcon import testing

from app import test_grouping
from keri import kering
from keri.app import habbing, agenting, storing, grouping
from keri.core import coring, eventing, parsing
from keri.db import basing, dbing
from keri.vdr import viring, issuing, verifying


def test_credential_handlers(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True) as hab, \
            habbing.openHab(name="recp", transferable=True) as recp:
        app = falcon.App()

        reger = viring.Registry(name=hab.name, temp=True)
        issuer = issuing.Issuer(hab=hab, name=hab.name, reger=reger, noBackers=True)

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hab=hab)
        verifier = verifying.Verifier(hab=hab, name="verifier")

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

        assert bytes(kiwi.cms) == cred

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
    with habbing.openHab(name="test", transferable=True) as hab, \
            habbing.openHab(name="recp", transferable=True) as recp:
        app = falcon.App()

        gid = "EyfirWU1lrFwWJOKfvhVjHZ9ADJwbLFzw04wb8SUP_0c"
        par1 = "ENJCK8DmQt5CV9cYI_5fchKtD3JFbdCDKvDiaESDK2-g"

        group = basing.GroupIdentifier(lid=hab.pre, gid=gid, dig="", cst="1", aids=[hab.pre, par1])
        hab.db.gids.put("test-group", group)

        reger = viring.Registry(name=hab.name, temp=True)
        issuer = issuing.Issuer(hab=hab, name=hab.name, reger=reger, noBackers=True)

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hab=hab)
        verifier = verifying.Verifier(hab=hab, name="verifier")

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
        assert cue["group"] == "test-group"
        assert cue["op"] == grouping.Ops.ixn
        assert cue["data"] == [dict(
            i="EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0",
            s="0",
            d="EnfAA4Gqw05dzKCdbfH2D13_FRYKg-sJw1dzH1oW6EM8"
        )]

        assert bytes(kiwi.cms) == cred

        result = client.simulate_post(path="/credential/revoke",
                                      body=b'{"registry": "E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38", "said": '
                                           b'"EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0"}')
        assert result.status == falcon.HTTP_CONFLICT
        assert result.text == ("Invalid revoke of EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0 that has not been "
                               "issued pre=E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38.")


def test_issue_credential_full_multisig():
    with test_grouping.openMutlsig(prefix="test") as (hab1, hab2, hab3), \
            habbing.openHab(name="recp", transferable=True) as recp:

        # Verify the group identifier was incepted properly and matches the identifiers
        assert hab1.pre == "ELQoqCOdxWcd3zhQTW7io5XJYAJLmhpbY8YqQF0sxZLo"
        assert hab2.pre == "EH-i-vxKSbaJQtal3V_ltrtjs7O1nuCHn4iqxdvdGOj0"
        assert hab3.pre == "EuK3T40uWRDXGZF9YApOjoTkLeDjjr7UPUqfCp5B04Fo"

        gid = "EbRGD66vYtbohJwGh-B2uPwHUDH3WrLcc_1Gn1ksSEu0"
        group1 = hab1.db.gids.get("g_test_1")
        assert group1.gid == gid
        assert group1.lid == hab1.pre
        group2 = hab2.db.gids.get("g_test_2")
        assert group2.gid == gid
        assert group2.lid == hab2.pre
        group3 = hab3.db.gids.get("g_test_3")
        assert group3.gid == gid
        assert group3.lid == hab3.pre

        # Now create the Falcon app and the Kiwi Server
        # with one of the Group participants Habitats
        app = falcon.App()

        reger = viring.Registry(name=hab1.name, temp=True)
        issuer = issuing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)

        issuers = dict()
        issuers[issuer.regk] = issuer
        repd = storing.Respondant(hab=hab1)
        verifier = verifying.Verifier(hab=hab1, name="verifier")

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

        # The Issuer will have cue'd up a multisig request to be processed
        assert len(issuer.cues) == 1
        cue = issuer.cues.popleft()
        assert cue["kin"] == "multisig"

        # Mimic the Doified loop in Kiwi server to process the cue for each participant
        msg = dict(
            op=cue["op"],
            group=cue["group"],
            data=cue["data"],
        )

        g1 = grouping.Groupy(hab=hab1)
        g2 = grouping.Groupy(hab=hab2)
        g3 = grouping.Groupy(hab=hab3)

        # Run the cue'd up multisig event thru Groupy objects to get an IXN event generated and signed
        missing = False
        try:
            g1.processMessage(f"g_test_1", msg)
        except kering.MissingSignatureError:
            missing = True

        assert missing is True

        # Original cue was for g1 so update the group name
        missing = False
        msg["group"] = "g_test_2"
        try:
            g2.processMessage(f"g_test_2", msg)
        except kering.MissingSignatureError:
            missing = True

        assert missing is True

        # Original cue was for g1 so update the group name
        missing = False
        msg["group"] = "g_test_3"
        try:
            g3.processMessage(f"g_test_3", msg)
        except kering.MissingSignatureError:
            missing = True

        assert missing is True

        assert hab1.kever.sn == 1
        assert hab2.kever.sn == 1
        assert hab3.kever.sn == 1

        assert hab1.kever.ilk == coring.Ilks.ixn
        assert hab2.kever.ilk == coring.Ilks.ixn
        assert hab3.kever.ilk == coring.Ilks.ixn

        raw = hab1.db.gpse.getLast("g_test_1")
        msg = json.loads(raw)
        gid = msg["pre"]
        dig = msg["dig"]

        dgkey = dbing.dgKey(gid, dig)
        eraw = hab1.db.getEvt(dgkey)
        mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event

        dgkey = dbing.dgKey(mssrdr.preb, mssrdr.digb)
        sigs = hab1.db.getSigs(dgkey)
        sigs.extend(hab2.db.getSigs(dgkey))
        sigs.extend(hab3.db.getSigs(dgkey))

        sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]

        evt = bytearray(eraw)
        evt.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=len(sigers)).qb64b)  # attach cnt
        for sig in sigs:
            evt.extend(sig)

        # Kevery for each Hab to process the IXM event
        kev1 = eventing.Kevery(db=hab1.db, lax=False, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=False, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=False, local=False)

        parsing.Parser().parse(ims=bytearray(evt), kvy=kev3)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev2)
        parsing.Parser().parse(ims=bytearray(evt), kvy=kev1)

        assert mssrdr.ked["a"] is not None
        assert mssrdr.ked["t"] == coring.Ilks.ixn
