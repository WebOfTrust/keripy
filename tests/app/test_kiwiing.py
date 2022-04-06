# -*- encoding: utf-8 -*-
"""
tests.app.agent_kiwiserver module

"""
import json
import os

import falcon
from falcon import testing

from keri import kering
from keri.app import habbing, storing, kiwiing, grouping
from keri.app.kiwiing import MultisigEventEnd
from keri.core import eventing, parsing, coring
from keri.db import basing
from keri.end import ending
from keri.vc import proving
from keri.vdr import viring, credentialing, verifying
from tests.app import test_grouping


def test_credential_handlers(mockHelpingNowUTC, seeder):
    with habbing.openHab(name="test", transferable=True) as (hby, hab), \
            habbing.openHab(name="recp", transferable=True) as (recpHby, recp):
        seeder.seedSchema(hby.db)
        seeder.seedSchema(recpHby.db)

        app = falcon.App()

        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        issuer = regery.makeRegistry(name=hab.name, prefix=hab.pre)
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)

        icp = recp.makeOwnEvent(sn=0)
        kvy = eventing.Kevery(db=hab.db, lax=True)
        parsing.Parser().parseOne(ims=bytearray(icp), kvy=kvy)

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        assert cue["kin"] == "kevt"
        cue = issuer.cues.popleft()
        assert cue["kin"] == "send"

        repd = storing.Respondant(hby=hby)
        counselor = grouping.Counselor(hby=hby)

        _ = kiwiing.loadEnds(hby=hby,
                             rep=repd,
                             rgy=regery,
                             verifier=verifier,
                             counselor=counselor,
                             app=app, path="/", mbx=None)

        client = testing.TestClient(app)

        result = client.simulate_post(path="/registries", body=b'{}')
        assert result.status == falcon.HTTP_400  # Bad request, missing name

        result = client.simulate_post(path="/registries", body=b'{"name": "test"}')
        assert result.status == falcon.HTTP_400  # Bad Request, missing alias

        result = client.simulate_post(path="/registries", body=b'{"name": "test", "alias": "test123"}')
        assert result.status == falcon.HTTP_404  # Bad Request, invalid alias

        # Test all the parameters
        result = client.simulate_post(path="/registries",
                                      body=b'{"name": "test-full", "alias": "test",'
                                           b' "noBackers": true, "baks": [], "toad": 0, "estOnly": false}')
        assert result.status == falcon.HTTP_202

        result = client.simulate_post(path="/registries", body=b'{"name": "test", "alias": "test"}')
        assert result.status == falcon.HTTP_202

        result = client.simulate_get(path="/registries")
        assert result.status == falcon.HTTP_200
        assert result.json == [{'name': 'test',
                                'pre': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                'regk': 'EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs',
                                'state': {'a': {'d': 'EhUlcH33N486ITfJu3kG5evVLoivVaR8Wp6ut8rP21gs', 's': 1},
                                          'b': [],
                                          'ba': [],
                                          'br': [],
                                          'bt': '0',
                                          'c': ['NB'],
                                          'd': 'EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs',
                                          'dt': '2021-01-01T00:00:00.000000+00:00',
                                          'et': 'vcp',
                                          'i': 'EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs',
                                          'ii': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                          's': '0',
                                          'v': 'KERI10JSON000158_'}}]

        schema = "EzvqGGnDksl5b92NPbVXhQg56p9Rf2OGeu_RjbEAtv-A"
        LEI = "1234567890abcdefg"

        data = dict(LEI=LEI)
        body = dict(
            alias="test",
            registry="test",
            schema=schema,
            recipient=recp.pre,
            type="GLEIFvLEICredential",
            credentialData=data, source=[], rules=[]
        )
        b = json.dumps(body).encode("utf-8")
        result = client.simulate_post(path="/credentials", body=b)
        assert result.status == falcon.HTTP_200

        tevt = (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EJwzM4hwvzoQnRAqXOtKynvC'
                b'Llt83WzjKx9OUVUs82qc","i":"EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RX'
                b'mlaWYW0","s":"0","ri":"EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482K'
                b'PDs","dt":"2021-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAA'
                b'AAAAAAAAgE0OHFMe-_ppaT2YBoJIpVn3A-lv1WcER3GoK_aPlNqGI')
        kevt = (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"E0OHFMe-_ppaT2YBoJIpVn3A'
                b'-lv1WcER3GoK_aPlNqGI","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpB'
                b'GF9Z1Pc","s":"2","p":"EhUlcH33N486ITfJu3kG5evVLoivVaR8Wp6ut8rP21'
                b'gs","a":[{"i":"EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RXmlaWYW0","s"'
                b':"0","d":"EJwzM4hwvzoQnRAqXOtKynvCLlt83WzjKx9OUVUs82qc"}]}-AABAA'
                b'sttu9Dtj72cP_Qx_o5c9HAuROPVN6tf_ABide4hT6eXKxRHV52Q9FCnOgsSWSERE'
                b'2Gy4TO4Oc8A3NvSbu9SGDg')
        cred = (b'{"v":"ACDC10JSON0001a2_","d":"EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RXmlaWYW0",'
                b'"s":"EzvqGGnDksl5b92NPbVXhQg56p9Rf2OGeu_RjbEAtv-A","i":"ECtWlHS2Wbx5M2Rg6nm6'
                b'9PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"EGtpMEB96XgfrN5CzxbRSDaRWVqH-78zrCk1N3gX'
                b'NaOE","i":"EqwblUykZNwSsBd4g8pHeRZhlkPj64MhoGDspLCh2qnI","dt":"2021-01-01T00'
                b':00:00.000000+00:00","LEI":"1234567890abcdefg"},"e":[],"ri":"EjPXk1a_MtWR3a0'
                b'qrZiJ34c971FxiHyCZSRo6482KPDs","r":[]}')

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == kevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == tevt

        creder = proving.Creder(raw=cred)
        assert regery.reger.creds.get(b'EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RXmlaWYW0').raw == creder.raw

        # Try to revoke a credential that doesn't exist and get the appropriate error
        result = client.simulate_delete(path="/credentials",
                                        query_string=("alias=test&"
                                                      "registry=test&"
                                                      "said=ESRIYQwCs8z1Fu7Jc6wf1ZDSoQQbKgjW9PiC324D_MUs"))
        assert result.status == falcon.HTTP_NOT_FOUND

        # Now revoke the actual credential
        result = client.simulate_delete(path="/credentials",
                                        query_string=("alias=test&"
                                                      "registry=test&"
                                                      "said=EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RXmlaWYW0"))
        assert result.status == falcon.HTTP_202

        rev = (b'{"v":"KERI10JSON000120_","t":"rev","d":"EtSxl8hO39oSn-Mu76dYT-iW'
               b'hkxFB2mxD5LCVvZftN78","i":"EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RX'
               b'mlaWYW0","s":"1","ri":"EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482K'
               b'PDs","p":"EJwzM4hwvzoQnRAqXOtKynvCLlt83WzjKx9OUVUs82qc","dt":"20'
               b'21-01-01T00:00:00.000000+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwE7X6'
               b'XkGS-mNlfMVMgk2itioHGRNTkio9K9-XvUrXL2iU')
        rkevt = (b'{"v":"KERI10JSON00013a_","t":"ixn","d":"E7X6XkGS-mNlfMVMgk2itioH'
                 b'GRNTkio9K9-XvUrXL2iU","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpB'
                 b'GF9Z1Pc","s":"3","p":"E0OHFMe-_ppaT2YBoJIpVn3A-lv1WcER3GoK_aPlNq'
                 b'GI","a":[{"i":"EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RXmlaWYW0","s"'
                 b':"1","d":"EtSxl8hO39oSn-Mu76dYT-iWhkxFB2mxD5LCVvZftN78"}]}-AABAA'
                 b'Tkkrdu2obr76kfCUJsVMD6qLdfWDFUe2w_PvhfjrLot--wZ4BUsEwHXvvODprZ6S'
                 b'eOwFmsPf9N45lZm0s0otCQ')

        assert len(issuer.cues) == 2
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == rkevt
        cue = issuer.cues.popleft()
        evt = cue["msg"]
        assert evt == rev

        result = client.simulate_get(path="/credentials", params=dict(type="issued", alias="test123", registry="test"))
        assert result.status == falcon.HTTP_400  # Bad Request, invalid alias

        result = client.simulate_get(path="/credentials", params=dict(type="issued", alias="test", registry="test"))
        assert result.status == falcon.HTTP_200
        assert result.json == [{'chains': [],
                                'pre': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                'sad': {'a': {'LEI': '1234567890abcdefg',
                                              'd': 'EGtpMEB96XgfrN5CzxbRSDaRWVqH-78zrCk1N3gXNaOE',
                                              'dt': '2021-01-01T00:00:00.000000+00:00',
                                              'i': 'EqwblUykZNwSsBd4g8pHeRZhlkPj64MhoGDspLCh2qnI'},
                                        'd': 'EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RXmlaWYW0',
                                        'e': [],
                                        'i': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                        'r': [],
                                        'ri': 'EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs',
                                        's': 'EzvqGGnDksl5b92NPbVXhQg56p9Rf2OGeu_RjbEAtv-A',
                                        'v': 'ACDC10JSON0001a2_'},
                                'sadcigars': [],
                                'sadsigers': [{'d': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                               'path': '-',
                                               'pre': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                               'sn': 0}],
                                'status': {'a': {'d': 'E7X6XkGS-mNlfMVMgk2itioHGRNTkio9K9-XvUrXL2iU', 's': 3},
                                           'd': 'EtSxl8hO39oSn-Mu76dYT-iWhkxFB2mxD5LCVvZftN78',
                                           'dt': '2021-01-01T00:00:00.000000+00:00',
                                           'et': 'rev',
                                           'i': 'EqwyiM0_aCQDgkPeOULSgRXhmwsxO_zI0C9RXmlaWYW0',
                                           'ra': {},
                                           'ri': 'EjPXk1a_MtWR3a0qrZiJ34c971FxiHyCZSRo6482KPDs',
                                           's': '1',
                                           'v': 'KERI10JSON000135_'}}]

        req = dict(alias="test",
                   schema="EtSxl8hO39oSn-Mu76dYT-iWhkxFB2mxD5LCVvZftN78",
                   issuer="ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc",
                   values={}
                   )
        b = json.dumps(req).encode("utf-8")
        result = client.simulate_post(path="/applications", body=b)
        assert result.status == falcon.HTTP_202
        req["alias"] = "test123"
        b = json.dumps(req).encode("utf-8")
        result = client.simulate_post(path="/applications", body=b)
        assert result.status == falcon.HTTP_400  # Bad Request, invalid alias


# def test_credential_handlers_singlesig(mockHelpingNowUTC):
#     with test_grouping.openMutlsig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)), \
#             habbing.openHab(name="recp", transferable=True) as (recpHby, recp):
#         app = falcon.App()
#
#         ims = bytearray()
#         reger = viring.Registry(name=hab1.name, temp=True)
#         verifier = verifying.Verifier(hby=hby1, reger=reger)
#         issuer = credentialing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)
#         gdoer = grouping.MultiSigGroupDoer(hby=hby1, ims=ims)
#         issuerCues = decking.Deck()
#
#         issuers = dict()
#         issuers[issuer.regk] = issuer
#         repd = storing.Respondant(hby=hby1)
#
#         _ = kiwiing.loadEnds(hby=hby1,
#                              rep=repd,
#                              verifier=verifier,
#                              gdoer=gdoer,
#                              issuers=issuers,
#                              issuerCues=issuerCues,
#                              app=app, path="/", mbx=None)
#
#         client = testing.TestClient(app)
#
#         result = client.simulate_post(path="/registries", body=b'{"name": "test", "alias": "test"}')
#         assert result.status == falcon.HTTP_202
#
#         schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
#         LEI = "1234567890abcdefg"
#
#         data = dict(LEI=LEI)
#         body = dict(
#             alias="test_1",
#             registry="test",
#             schema=schema,
#             recipient=recp.pre,
#             type="GLEIFvLEICredential",
#             credentialData=data
#         )
#         b = json.dumps(body).encode("utf-8")
#         result = client.simulate_post(path="/credentials", body=b)
#         assert result.status == falcon.HTTP_200
#         assert len(issuer.cues) == 1
#
#         cue = issuer.cues.popleft()
#         assert cue["kin"] == "multisig"
#         assert cue["op"] == grouping.Ops.ixn
#         assert cue["data"] == [
#             {'d': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              'i': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              's': '0'}
#         ]
#
#         result = client.simulate_delete(path="/credentials",
#                                         query_string=("alias=test&"
#                                                       "registry=E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38&"
#                                                       "said=EhkvrkfiAkI88LBHk48hsMQSKmxHvk3Oktf7IDO2iVC0"))
#         assert result.status == falcon.HTTP_NOT_FOUND
#         assert result.text == "credential not found"


# def test_issue_credential_full_multisig():
#     with test_grouping.openMutlsig(prefix="test") as ((hby1, hab1), (hby2, hab2), (hby3, hab3)), \
#             habbing.openHab(name="recp", transferable=True) as recp:
#         # Verify the group identifier was incepted properly and matches the identifiers
#         assert hab1.pre == "El5WIVmMSnNIsa3Oqib-g5BNkK8uwKOrFvxxPJ_jM5I8"
#         assert hab2.pre == "ESXQU9TMcdFiuVNRxe6YrbeYlwZJn04UyJUEJxR36Qyw"
#         assert hab3.pre == "EHDoHoAMCI4iRgOjNKYuSLdxsATl9mWCN3HlzOptd2XA"
#
#         gid = "Ea69OZWwWIVBvwX5a-LJjg8VAsc7sTL_OlxBHPdhKjow"
#         group1 = hab1.db.gids.get(hab1.pre)
#         assert group1.gid == gid
#         group2 = hab2.db.gids.get(hab2.pre)
#         assert group2.gid == gid
#         group3 = hab3.db.gids.get(hab3.pre)
#         assert group3.gid == gid
#
#         # Now create the Falcon app and the Kiwi Server
#         # with one of the Group participants Habitats
#         app = falcon.App()
#
#         reger = viring.Registry(name=hab1.name, temp=True)
#         verifier = verifying.Verifier(hby=hby1, reger=reger)
#         issuer = credentialing.Issuer(hab=hab1, name=hab1.name, reger=reger, noBackers=True)
#         witq = agenting.WitnessInquisitor(hby=hby1, reger=verifier.reger, klas=agenting.HttpWitnesser)
#         issuerCues = decking.Deck()
#
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#         assert cue["kin"] == "multisig"
#         assert cue["data"] == [
#             {'d': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              'i': 'Exe1r9MGB7C5H0YvoqiiyB7sQl1-Ahv9YdBjqNjImQ70',
#              's': '0'}
#         ]
#
#         ims = bytearray()
#         issuers = dict()
#         issuers[issuer.regk] = issuer
#         repd = storing.Respondant(hby=hby1)
#         gdoer = grouping.MultiSigGroupDoer(hby=hby1, ims=ims)
#
#         _ = kiwiing.loadEnds(hby=hby1,
#                              rep=repd,
#                              verifier=verifier,
#                              gdoer=gdoer,
#                              issuers=issuers,
#                              issuerCues=issuerCues,
#                              app=app, path="/", mbx=None)
#
#         # Create the credential to be issued
#         schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
#         LEI = "1234567890abcdefg"
#
#         data = dict(LEI=LEI)
#         body = dict(
#             registry=issuer.regk,
#             schema=schema,
#             source=hab1.pre,
#             recipient=recp.pre,
#             type="GLEIFvLEICredential",
#             credentialData=data
#         )
#         b = json.dumps(body).encode("utf-8")
#
#         # Use Falcon test all to submit the request to issue a credential
#         client = testing.TestClient(app)
#         result = client.simulate_post(path="/credentials", body=b)
#         assert result.status == falcon.HTTP_200
#
#         creder = proving.Creder(ked=result.json, kind=coring.Serials.json)
#
#         # The Issuer will have cue'd up a multisig request to be processed
#         assert len(issuer.cues) == 1
#         cue = issuer.cues.popleft()
#
#         assert cue["kin"] == "multisig"
#         data = cue["data"]
#         assert len(data) == 1
#         assert data[0]['s'] == '0'
#         assert data[0]['i'] == creder.saider.qb64
#         assert 'd' in data[0]


def test_multisig_incept():
    prefix = "ends_test"
    salt = b'0123456789abcdef'
    with habbing.openHab(name=f"{prefix}_1", salt=salt, transferable=True, temp=True) as (hby1, hab1), \
            habbing.openHab(name=f"{prefix}_2", salt=salt, transferable=True, temp=True) as (hby2, hab2), \
            habbing.openHab(name=f"{prefix}_3", salt=salt, transferable=True, temp=True) as (hby3, hab3):
        kev1 = eventing.Kevery(db=hab1.db, lax=False, local=False)
        kev2 = eventing.Kevery(db=hab2.db, lax=False, local=False)
        kev3 = eventing.Kevery(db=hab3.db, lax=False, local=False)

        icp1 = hab1.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev2)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp1), kvy=kev3)
        icp2 = hab2.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp2), kvy=kev3)
        icp3 = hab3.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev1)
        parsing.Parser().parse(ims=bytearray(icp3), kvy=kev2)

        assert hab1.pre == "E1plfvtsnS6XwiHOxF6n3fUTs-ylvJsxIUCd2Ji4hNqc"
        assert hab2.pre == "EmYIWxzWUtSfQNBodo5RT8hNjoFlzcXZXTQXQM500tyE"
        assert hab3.pre == "EPrbmW_c_3Dp4Q6rddi5X7RHp_Xkjp21RcMG2FEWr_HI"

        counselor = grouping.Counselor(hby=hby1)
        icpEnd = kiwiing.MultisigInceptEnd(hby=hby1, counselor=counselor)
        app = falcon.App()
        app.add_route("/multisig/{alias}/icp", icpEnd)

        client = testing.TestClient(app)

        # aids is required
        result = client.simulate_post(path="/multisig/test/icp", body=b'{}')
        assert result.status == falcon.HTTP_400
        assert result.text == "Invalid multisig group inception request, 'aids' is required'"

        # aids must include a local identifier
        body = dict(group="test", aids=[hab2.pre, hab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path="/multisig/test/icp", body=b)
        assert result.status == falcon.HTTP_400
        assert result.text == ('Invalid multisig group inception request, aid list must contain a local '
                               "identifier'")

        # can not reuse a hab alias
        body = dict(aids=[hab1.pre, hab2.pre, hab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path=f"/multisig/{prefix}_1/icp", body=b)
        assert result.status == falcon.HTTP_400
        assert result.text == "Identifier alias ends_test_1 is already in use"

        body = dict(
            aids=[hab1.pre, hab2.pre, hab3.pre],
            transferable=True,
            wits=[
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            toad=2,
            isith=2,
            nsith=2

        )
        b = json.dumps(body).encode("utf-8")

        # Use Falcon test all to submit the request to issue a credential
        client = testing.TestClient(app)
        result = client.simulate_post(path="/multisig/multisig/icp", body=b)
        assert result.status == falcon.HTTP_200
        assert len(icpEnd.postman.evts) == 2

        # Incept POST endpoint initiates multisig inception by sending the ICP to all other participants
        evt = icpEnd.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab2.pre
        srdr = evt["serder"]
        assert srdr.ked['t'] == coring.Ilks.exn
        assert srdr.ked['r'] == '/multisig/icp'
        payload = json.dumps(srdr.ked["a"]).encode("utf-8")
        assert payload == (b'{"aids": ["E1plfvtsnS6XwiHOxF6n3fUTs-ylvJsxIUCd2Ji4hNqc", "EmYIWxzWUtSfQNBod'
                           b'o5RT8hNjoFlzcXZXTQXQM500tyE", "EPrbmW_c_3Dp4Q6rddi5X7RHp_Xkjp21RcMG2FEWr_HI"'
                           b'], "ked": {"v": "KERI10JSON000273_", "t": "icp", "d": "EaPj6HOFtnnvbNKlFLwb3'
                           b'lVTOZBvRxdSGlEpZVLFLU6U", "i": "EaPj6HOFtnnvbNKlFLwb3lVTOZBvRxdSGlEpZVLFLU6U'
                           b'", "s": "0", "kt": "2", "k": ["DZahe53x0zi5u3BEGPEdnYHePZ1uU1tE317OOSUNRqqg"'
                           b', "DUrtOqQyjGz_CkXkgPblFlQFvmjD3eQ_ivdGR6bPjUaU", "D_3nA6zRH1IYiA5oL6ClYeUm2'
                           b'vA--AN4_7T5UspmFqZY"], "nt": "2", "n": ["Em9F-auLKTY-KStSxCI4m4VlnIJlcaruPjP'
                           b'oQGk_FFT4", "Eo1ouQV2441h2Hg8cPD3D0YJg5eCzRKFFN3Dc-QYwPas", "Epxv4r1j0khdLvL'
                           b'_y0gTrTsCKd3Kv_iKAiBtF-mDlzLg"], "bt": "2", "b": ["BGKVzj4ve0VSd8z_AmvhLg4lq'
                           b'cC_9WYX90k03q-R_Ydo", "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw", "Bgoq6'
                           b'8HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"], "c": [], "a": []}}')

        evt = icpEnd.postman.evts.popleft()
        assert evt["src"] == hab1.pre
        assert evt["dest"] == hab3.pre
        assert evt["serder"] == srdr

        # Create new end and app to represent Hab2's agent
        counselor = grouping.Counselor(hby=hby2)
        icpEnd = kiwiing.MultisigInceptEnd(hby=hby2, counselor=counselor)
        app = falcon.App()
        app.add_route("/multisig/{alias}/icp", icpEnd)

        client = testing.TestClient(app)

        # Perform a PUT to join a group identifier inception
        result = client.simulate_put(path="/multisig/multisig2/icp", body=b)
        assert result.status == falcon.HTTP_200
        assert len(icpEnd.counselor.postman.evts) == 2
        evt = icpEnd.counselor.postman.evts.popleft()
        assert evt["src"] == hab2.pre
        assert evt["dest"] == hab1.pre
        assert evt["topic"] == "multisig"
        assert evt["serder"].raw == (b'{"v":"KERI10JSON000273_","t":"icp","d":"EaPj6HOFtnnvbNKlFLwb3lVTOZBvRxdSGlEp'
                                     b'ZVLFLU6U","i":"EaPj6HOFtnnvbNKlFLwb3lVTOZBvRxdSGlEpZVLFLU6U","s":"0","kt":"2'
                                     b'","k":["DZahe53x0zi5u3BEGPEdnYHePZ1uU1tE317OOSUNRqqg","DUrtOqQyjGz_CkXkgPblF'
                                     b'lQFvmjD3eQ_ivdGR6bPjUaU","D_3nA6zRH1IYiA5oL6ClYeUm2vA--AN4_7T5UspmFqZY"],"nt'
                                     b'":"2","n":["Em9F-auLKTY-KStSxCI4m4VlnIJlcaruPjPoQGk_FFT4","Eo1ouQV2441h2Hg8c'
                                     b'PD3D0YJg5eCzRKFFN3Dc-QYwPas","Epxv4r1j0khdLvL_y0gTrTsCKd3Kv_iKAiBtF-mDlzLg"]'
                                     b',"bt":"2","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZ'
                                     b'oapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh'
                                     b'9c"],"c":[],"a":[]}')
        assert evt["attachment"] == (b'-AABAB_ic5fv_CzcSzvhuM4ngRuzRhjlJRFVuRuZ8xr6dyhcoQJ7EmuBM90aSci3wC-dE1JItuW2HkhM'
                                     b'k2cBE2oOAVBA')
        evt = icpEnd.counselor.postman.evts.popleft()
        assert evt["src"] == hab2.pre
        assert evt["dest"] == hab3.pre


def test_multisig_rotation():
    prefix = "test"
    with test_grouping.openMutlsig(prefix="test") as ((hby1, ghab1), (hby2, ghab2), (hby3, ghab3)):
        assert ghab1.pre == ghab2.pre == ghab3.pre == "Ehysj8OgpMlUgoMVaMDY8Gn8nDhnc00vH82RrY1s2vrU"

        app = falcon.App()

        # Start with hby1 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby1)
        rotEnd = MultisigEventEnd(hby=hby1, counselor=counselor)
        app.add_route("/multisig/{alias}/rot", rotEnd, suffix="rot")

        client = testing.TestClient(app)

        # aids is required
        result = client.simulate_post(path="/multisig/test/rot", body=b'{}')
        assert result.status == falcon.HTTP_400
        assert result.text == "Invalid multisig group rotation request, 'aids' is required"

        # aids must include a local identifier
        body = dict(group="test", aids=[ghab2.pre, ghab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path="/multisig/test/rot", body=b)
        assert result.status == falcon.HTTP_404
        assert result.text == "Invalid multisig group rotation request alias {alias} not found"

        body = dict(
            aids=[ghab1.phab.pre, ghab2.phab.pre, ghab3.phab.pre],
            transferable=True,
            wits=[
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            toad=2,
            isith=2,
            nsith=2

        )
        b = json.dumps(body).encode("utf-8")

        # initiate a multisig rotation with a POST
        client = testing.TestClient(app)
        result = client.simulate_post(path=f"/multisig/{prefix}_group1/rot", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for local witnessing
        assert hby1.db.glwe.get(keys=(ghab1.pre,)) is not None

        # sends local rotation event to other participants to start the rotation
        assert len(rotEnd.postman.evts) == 2
        evt = rotEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab2.phab.pre
        assert evt["topic"] == "multisig"
        evt = rotEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab3.phab.pre
        assert evt["topic"] == "multisig"
        payload = evt["serder"].ked["a"]
        assert set(payload['adds']) == {'BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo',
                                        'Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c',
                                        'BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw'}

        assert payload['aids'] == ['E07_pVCaF6sp9qv-_ufgnqfzySdauT1izcndWMwZzy6c',
                                   'E83mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068',
                                   'ELftDsGmYwRsd2lXjUqbky0vxABS4-VXeHV7OAIQzCQI']
        assert payload['cuts'] == []
        assert payload['sith'] == 2
        assert payload['toad'] == 2
        assert payload['data'] is None

        app = falcon.App()
        # Now join rotation with hby2 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby2)
        rotEnd = MultisigEventEnd(hby=hby2, counselor=counselor)
        app.add_route("/multisig/{alias}/rot", rotEnd, suffix="rot")
        client = testing.TestClient(app)
        result = client.simulate_put(path=f"/multisig/{prefix}_group2/rot", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for local witnessing
        glwe = hby2.db.glwe.get(keys=(ghab2.pre,))
        assert glwe is not None
        # no notifications set if joining
        assert len(rotEnd.postman.evts) == 0


def test_multisig_interaction():
    prefix = "test"
    with test_grouping.openMutlsig(prefix="test") as ((hby1, ghab1), (hby2, ghab2), (hby3, ghab3)), \
            habbing.openHab(name="recp", transferable=True) as (recpHby, recp):
        assert ghab1.pre == ghab2.pre == ghab3.pre == "Ehysj8OgpMlUgoMVaMDY8Gn8nDhnc00vH82RrY1s2vrU"

        app = falcon.App()

        # Start with hby1 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby1)
        evtEnd = MultisigEventEnd(hby=hby1, counselor=counselor)
        app.add_route("/multisig/{alias}/ixn", evtEnd, suffix="ixn")

        client = testing.TestClient(app)

        # aids is required
        result = client.simulate_post(path="/multisig/test/ixn", body=b'{}')
        assert result.status == falcon.HTTP_400
        assert result.text == "Invalid multisig group rotation request, 'aids' is required"

        # aids must include a local identifier
        body = dict(group="test", aids=[ghab2.pre, ghab3.pre])
        b = json.dumps(body).encode("utf-8")

        result = client.simulate_post(path="/multisig/test/ixn", body=b)
        assert result.status == falcon.HTTP_404
        assert result.text == "Invalid multisig group rotation request alias {alias} not found"

        body = dict(
            aids=[ghab1.phab.pre, ghab2.phab.pre, ghab3.phab.pre],
            data=dict(i=ghab3.phab.pre, s=0)
        )
        b = json.dumps(body).encode("utf-8")

        # initiate a multisig rotation with a POST
        client = testing.TestClient(app)
        result = client.simulate_post(path=f"/multisig/{prefix}_group1/ixn", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for all signatures
        assert hby1.db.gpse.get(keys=(ghab1.pre,)) is not None

        # sends local rotation event to other participants to start the rotation
        assert len(evtEnd.postman.evts) == 2
        evt = evtEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab2.phab.pre
        assert evt["topic"] == "multisig"
        evt = evtEnd.postman.evts.popleft()
        assert evt["src"] == ghab1.phab.pre
        assert evt["dest"] == ghab3.phab.pre
        assert evt["topic"] == "multisig"
        payload = evt["serder"].ked["a"]
        assert payload == {'aids': ['E07_pVCaF6sp9qv-_ufgnqfzySdauT1izcndWMwZzy6c',
                                    'E83mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068',
                                    'ELftDsGmYwRsd2lXjUqbky0vxABS4-VXeHV7OAIQzCQI'],
                           'data': {'i': 'ELftDsGmYwRsd2lXjUqbky0vxABS4-VXeHV7OAIQzCQI', 's': 0},
                           'gid': 'Ehysj8OgpMlUgoMVaMDY8Gn8nDhnc00vH82RrY1s2vrU'}

        app = falcon.App()
        # Now join rotation with hby2 who will initiate the rotation with a POST
        counselor = grouping.Counselor(hby=hby1)
        evtEnd = MultisigEventEnd(hby=hby2, counselor=counselor)
        app.add_route("/multisig/{alias}/ixn", evtEnd, suffix="ixn")
        client = testing.TestClient(app)
        result = client.simulate_put(path=f"/multisig/{prefix}_group2/ixn", body=b)
        assert result.status == falcon.HTTP_202

        # escrow event for all signatures
        assert hby2.db.gpse.get(keys=(ghab2.pre,)) is not None
        # no notifications set if joining
        assert len(evtEnd.postman.evts) == 0


def test_identifier_ends():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        assert hab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        app = falcon.App()

        reger = viring.Reger(name=hab.name, temp=True)
        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        verifier = verifying.Verifier(hby=hby, reger=reger)

        repd = storing.Respondant(hby=hby)
        counselor = grouping.Counselor(hby=hby)

        endDoers = kiwiing.loadEnds(hby=hby,
                                    rep=repd,
                                    rgy=regery,
                                    verifier=verifier,
                                    app=app, path="/",
                                    mbx=None, counselor=counselor)
        client = testing.TestClient(app)

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [{'isith': '1',
                                'name': 'test',
                                'next_keys': ['EsBMmyevdbrDojd73T6UmBvSktf7f-i-Yu0LjsuRr7y4'],
                                'nsith': '1',
                                'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                'public_keys': ['DaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg'],
                                'receipts': 0,
                                'seq_no': 0,
                                'toad': 0,
                                'witnesses': []}]

        req = dict(isith=1, count=1)
        result = client.simulate_put(path="/ids/test/rot", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.json == {'a': [],
                               'ba': [],
                               'br': [],
                               'bt': '0',
                               'd': 'EawlnQ8c4obp5urfda9tBLdeWQuYN7caxxIZYXjABFRY',
                               'i': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'k': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                               'kt': '1',
                               'n': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                               'nt': '1',
                               'p': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               's': '1',
                               't': 'rot',
                               'v': 'KERI10JSON000160_'}

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200

        assert result.json == [{'isith': '1',
                                'name': 'test',
                                'next_keys': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                                'nsith': '1',
                                'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                                'receipts': 0,
                                'seq_no': 1,
                                'toad': 0,
                                'witnesses': []}]

        req = dict(transferable=True, wits=[], toad=0, isith=1, count=1, nsith=1, ncount=1, estOnly=False)
        result = client.simulate_post(path="/ids/test2", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        assert result.json == {'a': [],
                               'b': [],
                               'bt': '0',
                               'c': [],
                               'd': 'EWJA1LHU3Du10uW9B0pM8e7xIQ_3CP3qp9a-D713MlxM',
                               'i': 'EWJA1LHU3Du10uW9B0pM8e7xIQ_3CP3qp9a-D713MlxM',
                               'k': ['D5TEUWL-32q6KlG8DMiygL-6hBeGlMh7rZjR8l9-kSPU'],
                               'kt': '1',
                               'n': ['EurslVC_9AbgETqNkP8xXewQyUxeICfbSy5hrFX5Dh3s'],
                               'nt': '1',
                               's': '0',
                               't': 'icp',
                               'v': 'KERI10JSON00012b_'}

        # Try to reuse the alias
        req = dict(transferable=True, wits=[], toad=0, isith=1, count=1, nsith=1, ncount=1, estOnly=False)
        result = client.simulate_post(path="/ids/test2", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_400

        # Create a delegated identifier
        req = dict(transferable=True, wits=[], toad=0, isith=1, count=1, nsith=1, ncount=1, estOnly=False,
                   delpre="ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc")
        result = client.simulate_post(path="/ids/test3", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        assert result.json == {'a': [],
                               'b': [],
                               'bt': '0',
                               'c': [],
                               'd': 'EuPLuLyLTdXSFnYpIN4shnvWwt6ufh-RHLssRjHcmr7I',
                               'di': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'i': 'EuPLuLyLTdXSFnYpIN4shnvWwt6ufh-RHLssRjHcmr7I',
                               'k': ['DwiTSOvj8HtydZQ24HuVYuUxC80kzq49DanESrU3g4wg'],
                               'kt': '1',
                               'n': ['ERQq0RyQ3nN97chiuWJSjxS3fdtPbDWZ9MmRzdQtLIk4'],
                               'nt': '1',
                               's': '0',
                               't': 'dip',
                               'v': 'KERI10JSON00015f_'}

        result = client.simulate_get(path="/ids")
        assert result.status == falcon.HTTP_200
        assert len(result.json) == 3
        assert result.json[2] == {'anchored': False,
                                  'delegated': True,
                                  'delegator': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                  'isith': '1',
                                  'name': 'test3',
                                  'next_keys': ['ERQq0RyQ3nN97chiuWJSjxS3fdtPbDWZ9MmRzdQtLIk4'],
                                  'nsith': '1',
                                  'prefix': 'EuPLuLyLTdXSFnYpIN4shnvWwt6ufh-RHLssRjHcmr7I',
                                  'public_keys': ['DwiTSOvj8HtydZQ24HuVYuUxC80kzq49DanESrU3g4wg'],
                                  'receipts': 0,
                                  'seq_no': 0,
                                  'toad': 0,
                                  'witnesses': []}

        req = dict(data=[{"i": 1, "s": 0, "d": 2}])
        result = client.simulate_put(path="/ids/test/ixn", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200

        assert result.json == {'a': [{'d': 2, 'i': 1, 's': 0}],
                               'd': 'EMNnpGzsaDEsYMhGsAlGX3VX0DE78rGzuEdj4l_HY49A',
                               'i': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'p': 'EawlnQ8c4obp5urfda9tBLdeWQuYN7caxxIZYXjABFRY',
                               's': '2',
                               't': 'ixn',
                               'v': 'KERI10JSON0000de_'}

        req = dict(id="ignored", name="Wile", company="ACME")
        result = client.simulate_put("/ids/bad", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_404  # Unknown alias

        result = client.simulate_put("/ids/test", body=json.dumps(req).encode("utf-8"))
        assert result.status == falcon.HTTP_200
        res = dict(req)
        res["id"] = "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"
        assert result.json == res

        # Test single GET with metadata
        result = client.simulate_get("/ids/test")
        assert result.status == falcon.HTTP_200
        assert result.json == {'isith': '1',
                               'metadata': {'company': 'ACME', 'name': 'Wile'},
                               'name': 'test',
                               'next_keys': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                               'nsith': '1',
                               'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                               'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                               'receipts': 0,
                               'seq_no': 2,
                               'toad': 0,
                               'witnesses': []}

        # Test list GET method with metadata
        result = client.simulate_get("/ids")
        assert result.status == falcon.HTTP_200
        assert result.json[0] == {'isith': '1',
                                  'metadata': {'company': 'ACME', 'name': 'Wile'},
                                  'name': 'test',
                                  'next_keys': ['ETkpPicDPIy1afc-RaNta91Rq7SkYQ7YhHS2AVY342Yk'],
                                  'nsith': '1',
                                  'prefix': 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
                                  'public_keys': ['DaA39fhkm-AAxCkPcKojluJ0qSCQItz_KT4-TVy6Wdc8'],
                                  'receipts': 0,
                                  'seq_no': 2,
                                  'toad': 0,
                                  'witnesses': []}

def test_oobi_ends(seeder):
    with habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby:
        wesHab = wesHby.makeHab(name="wes", transferable=False)

        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[wesHab.pre])

        assert palHab.pre == "E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A"

        oobiery = ending.Oobiery(db=palHby.db)
        app = falcon.App()
        _ = kiwiing.loadEnds(hby=palHby,
                             rep=None,
                             rgy=None,
                             verifier=None,
                             app=app, path="/",
                             mbx=None, counselor=None,
                             oobiery=oobiery)
        client = testing.TestClient(app)

        result = client.simulate_get(path="/oobi/test?role=witness")
        assert result.status == falcon.HTTP_400  # Bad alias, does not exist

        result = client.simulate_get(path="/oobi/pal?role=watcher")
        assert result.status == falcon.HTTP_404  # Bad role, watcher not supported yet

        result = client.simulate_get(path="/oobi/pal?role=witness")
        assert result.status == falcon.HTTP_404  # Missing OOBI endpoints for witness

        result = client.simulate_get(path="/oobi/pal?role=controller")
        assert result.status == falcon.HTTP_404  # Missing OOBI controller endpoints

        # Add controller endpoints
        url = "http://127.0.0.1:9999/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/controller"
        palHab.db.locs.put(keys=(palHab.pre, kering.Schemes.http), val=basing.LocationRecord(url=url))
        result = client.simulate_get(path="/oobi/pal?role=controller")
        assert result.status == falcon.HTTP_200  # Missing OOBI controller endpoints
        assert result.json == {'oobis':
                               ['http://127.0.0.1:9999/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/controller'],
                               'role': 'controller'}

        # Seed with witness endpoints
        seeder.seedWitEnds(palHby.db, protocols=[kering.Schemes.http, kering.Schemes.tcp])

        result = client.simulate_get(path="/oobi/pal?role=witness")
        assert result.status == falcon.HTTP_200
        assert result.json == {'oobis':
                               [('http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/'
                                 'B3y3efWXFxXRJYYkggXjp-lJSoDsyqt7kok03edvHeas')],
                               'role': 'witness'}

        data = dict(url="http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/")
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/oobi/pal", body=b)
        assert result.status == falcon.HTTP_202
        assert len(oobiery.oobis) == 1
        oobi = oobiery.oobis.popleft()
        assert oobi == {'alias': 'pal',
                        'url': 'http://127.0.0.1:5644/oobi/E6Dqo6tHmYTuQ3Lope4mZF_4hBoGJl93cBHRekr_iD_A/witness/'}


def test_challenge_ends(seeder):
    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby:
        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[])

        assert palHab.pre == "Eg-r6DSx1C4aReh2pwQsejJS-uPc6qb8OQ0qm30bKxcU"

        app = falcon.App()
        repd = storing.Respondant(hby=palHby)
        _ = kiwiing.loadEnds(hby=palHby,
                             rep=repd,
                             rgy=None,
                             verifier=None,
                             app=app, path="/",
                             mbx=None, counselor=None)
        client = testing.TestClient(app)

        result = client.simulate_get(path="/challenge?strength=256")
        assert result.status == falcon.HTTP_200
        assert "words" in result.json
        words = result.json["words"]
        assert len(words) == 24

        result = client.simulate_get(path="/challenge")
        assert result.status == falcon.HTTP_200
        assert "words" in result.json
        words = result.json["words"]
        assert len(words) == 12

        data = dict(
        )
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/challenge/joe", body=b)
        assert result.status == falcon.HTTP_400  # Bad allias
        result = client.simulate_post(path="/challenge/pal", body=b)
        assert result.status == falcon.HTTP_400  # Missing words

        data["words"] = words
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/challenge/pal", body=b)
        assert result.status == falcon.HTTP_400  # Missing recipient

        data["recipient"] = "Eo6MekLECO_ZprzHwfi7wG2ubOt2DWKZQcMZvTbenBNU"
        b = json.dumps(data).encode("utf-8")
        result = client.simulate_post(path="/challenge/pal", body=b)
        assert result.status == falcon.HTTP_202

        assert len(repd.reps) == 1
        rep = repd.reps.popleft()
        assert rep["topic"] == "challenge"
        assert rep["dest"] == "Eo6MekLECO_ZprzHwfi7wG2ubOt2DWKZQcMZvTbenBNU"
        assert rep["rep"].ked['r'] == '/challenge/response'


def test_contact_ends(seeder):
    with habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="ken", salt=coring.Salter(raw=b'0123456789ghijkl').qb64) as kenHby:

        palHab = palHby.makeHab(name="pal", icount=1, ncount=1, wits=[])
        kvy = eventing.Kevery(db=palHab.db, local=False, lax=True)
        assert palHab.pre == "Eg-r6DSx1C4aReh2pwQsejJS-uPc6qb8OQ0qm30bKxcU"

        msgs = bytearray()
        aids = []
        for i in range(5):
            hab = kenHby.makeHab(name=f"ken{i}", icount=1, ncount=1, wits=[])
            aids.append(hab.pre)
            msgs.extend(hab.makeOwnInception())

        hab = kenHby.makeHab(name="bad", icount=1, ncount=1, wits=[])
        msgs.extend(hab.makeOwnInception())
        parsing.Parser().parse(ims=msgs, kvy=kvy)

        for aid in aids:
            assert aid in palHab.kevers

        app = falcon.App()
        _ = kiwiing.loadEnds(hby=palHby,
                             rep=None,
                             rgy=None,
                             verifier=None,
                             app=app, path="/",
                             mbx=None, counselor=None)
        client = testing.TestClient(app)

        response = client.simulate_get("/contacts")
        assert response.status == falcon.HTTP_200
        assert response.json == []

        data = dict(
            name="test"
        )
        b = json.dumps(data).encode("utf-8")
        # POST to an identifier that is not in the Kever
        response = client.simulate_post("/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo", body=b)
        assert response.status == falcon.HTTP_404

        # POST to a local identifier
        response = client.simulate_post(f"/contacts/{palHab.pre}", body=b)
        assert response.status == falcon.HTTP_400

        for i in range(5):
            data = dict(
                id=aid[i],
                first=f"Ken{i}",
                last=f"Burns{i}",
                company="GLEIF"
            )
            b = json.dumps(data).encode("utf-8")
            # POST to an identifier that is not in the Kever
            response = client.simulate_post(f"/contacts/{aids[i]}", body=b)
            assert response.status == falcon.HTTP_200

        response = client.simulate_get(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{hab.pre}")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{aids[3]}")
        assert response.status == falcon.HTTP_200
        assert response.json == {'company': 'GLEIF',
                                 'first': 'Ken3',
                                 'id': 'EbmbYwDptKJwtvhvwp_832eepyfFgqBiUe_PWbPgq0kA',
                                 'last': 'Burns3'}

        response = client.simulate_get(f"/contacts")
        assert response.status == falcon.HTTP_200
        assert len(response.json) == 5
        data = {d["id"]: d for d in response.json}
        for aid in aids:
            assert aid in data

        data = dict(id=hab.pre, company="ProSapien")
        b = json.dumps(data).encode("utf-8")

        response = client.simulate_put(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo", body=b)
        assert response.status == falcon.HTTP_404

        response = client.simulate_put(f"/contacts/{palHab.pre}", body=b)
        assert response.status == falcon.HTTP_400

        response = client.simulate_put(f"/contacts/{aids[2]}", body=b)
        assert response.status == falcon.HTTP_200
        assert response.json == {'company': 'ProSapien',
                                 'first': 'Ken2',
                                 'id': 'EF2EBiBL7RJ84ilErw8PyMEbABX_wJIL2VHNqLOdq5cw',
                                 'last': 'Burns2'}
        response = client.simulate_put(f"/contacts/{aids[4]}", body=b)
        assert response.status == falcon.HTTP_200
        assert response.json == {'company': 'ProSapien',
                                 'first': 'Ken4',
                                 'id': 'EWgyARhlWPWWC3DD1kr-hKKR3EK10FUSpY78IGWrmf7M',
                                 'last': 'Burns4'}

        response = client.simulate_get("/contacts", query_string="group=company")
        assert response.status == falcon.HTTP_200

        gleif = response.json["GLEIF"]
        data = {d["id"]: d for d in gleif}
        assert aids[0] in data
        assert aids[1] in data
        assert aids[3] in data

        pros = response.json["ProSapien"]
        data = {d["id"]: d for d in pros}
        assert aids[2] in data
        assert aids[4] in data

        response = client.simulate_get("/contacts", query_string="filter_field=last")
        assert response.status == falcon.HTTP_400

        response = client.simulate_get("/contacts", query_string="filter_field=last&filter_value=Burns3")
        assert response.status == falcon.HTTP_200
        assert response.json == [{'company': 'GLEIF',
                                  'first': 'Ken3',
                                  'id': 'EbmbYwDptKJwtvhvwp_832eepyfFgqBiUe_PWbPgq0kA',
                                  'last': 'Burns3'}]

        response = client.simulate_delete(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert response.status == falcon.HTTP_404

        response = client.simulate_delete(f"/contacts/{aids[3]}")
        assert response.status == falcon.HTTP_202

        response = client.simulate_get("/contacts", query_string="filter_field=last&filter_value=Burns3")
        assert response.status == falcon.HTTP_200
        assert response.json == []

        data = bytearray(os.urandom(50))
        headers = {"Content-Type": "image/png", "Content-Length": "50"}
        response = client.simulate_post(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/img", body=data,
                                        headers=headers)
        assert response.status == falcon.HTTP_404

        data = bytearray(os.urandom(1000001))
        headers = {"Content-Type": "image/png", "Content-Length": "1000001"}
        response = client.simulate_post(f"/contacts/{aids[0]}/img", body=data, headers=headers)
        assert response.status == falcon.HTTP_400

        data = bytearray(os.urandom(10000))
        headers = {"Content-Type": "image/png", "Content-Length": "10000"}
        response = client.simulate_post(f"/contacts/{aids[0]}/img", body=data, headers=headers)
        assert response.status == falcon.HTTP_202

        response = client.simulate_get(f"/contacts/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo/img")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{aids[2]}/img")
        assert response.status == falcon.HTTP_404

        response = client.simulate_get(f"/contacts/{aids[0]}/img")
        assert response.status == falcon.HTTP_200
        assert response.content == data
        headers = response.headers
        assert headers["Content-Type"] == "image/png"
        assert headers["Content-Length"] == "10000"


def test_keystate_end():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        assert hab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        app = falcon.App()

        counselor = grouping.Counselor(hby=hby)

        endDoers = kiwiing.loadEnds(hby=hby,
                                    rep=None,
                                    rgy=None,
                                    verifier=None,
                                    app=app, path="/",
                                    mbx=None, counselor=counselor)
        client = testing.TestClient(app)

        result = client.simulate_get(path=f"/keystate/E8AKUcbZyik8EdkOwXgnyAxO5mSIPJWGZ_o7zMhnNnjo")
        assert result.status == falcon.HTTP_404

        result = client.simulate_get(path=f"/keystate/{hab.pre}")
        assert result.status == falcon.HTTP_200
        state = result.json["state"]
        assert state["i"] == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"
        assert state["et"] == "icp"
        assert state["k"] == ['DaYh8uaASuDjMUd8_BoNyQs3GwupzmJL8_RBsuNtZHQg']
        assert state["n"] == ['EsBMmyevdbrDojd73T6UmBvSktf7f-i-Yu0LjsuRr7y4']

        kel = result.json["kel"]
        assert len(kel) == 1




