# -*- encoding: utf-8 -*-
"""
keri.vc.handling module

"""
import json

from hio.base import doing
from hio.help import decking

from .. import help
from ..app import signing
from ..peer import exchanging

logger = help.ogler.getLogger()


class ApplyHandler(doing.Doer):
    """
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "d": "EvLi9I4T6tiIEi4IxZtQy8S7ec5SZYwKJnUBPIgYs5Ks",
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/credential/apply"
           "a" {
               "s": "EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw",
               "a": {
                  "LEI": "254900OPPU84GM83MG36"
               }
           } //embedded credential_submission, may contain credential_fullfilment responding to presentation_def above
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/credential/apply"

    def __init__(self, hby, rgy, verifier, name, cues=None, **kwa):
        """ Initialize instance

        Parameters:
            hab (Habitat): credential wallet that will hold the issued credentials
            verifier (Verifier): Local credential verifier used to verify and save any issued credential
            name (str): local alias of issuer to use for issuing credential
            issuerCues (Optional(decking.Deck)): outbound cue messages for issuer
            cues (Optional(decking.Deck)): outbound cue messages
            **kwa (dict): keyword arguments passed to DoDoer

        """
        self.hby = hby
        self.rgy = rgy
        self.verifier = verifier
        self.name = name
        self.issuer = None
        self.cues = cues if cues is not None else decking.Deck()

        self.msgs = decking.Deck()

        super(ApplyHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                recipientIdentifier = msg["pre"]
                print(recipientIdentifier)

                yield self.tock

            yield self.tock


class IssueHandler(doing.DoDoer):
    """ Sample class that handles a credential Issue `exn` message.

    By default, this handler verifies the credential with the provided verifier.
    The incoming message must have the following format:

         {
       "vc" [
         {
           "vc": {
              "v": "KERI10JSON00011c_", //KERI Version String
              "x": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the Schema
              "d": {
                   "type": [
                       "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI"
                   ],
                   "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                   "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",
                   "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                   "credentialSubject": {
                       "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                       "lei": "254900OPPU84GM83MG36"
                   },
                   "credentialSchema": {
                       "id": ""
                       "type": ""
                   },
                   "credentialStatus": {
                      "id": "",
                      "type": ""
                   }
              }
           }, // embedded verifiable credential
           "proof": "-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE
                 -d_ApsFEgCA-GAB0AAAAAAAAAAAAAAAAAAAAABQEchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA"
           }
       ]   //list of verifiable credentials
    }


    """

    resource = "/credential/issue"

    def __init__(self, hby, rgy, mbx, controller, **kwa):
        """ Initialize instance

        Parameters:
            hab (Habitat): local identifier environment
            wallet (Wallet) credential wallet that will hold the issued credentials
            ims (Optional(bytearray)): inbound message stream to process
            cues (Optional(decking.Deck)): outbound cue messages
            **kwa (dict): keyword arguments passed to DoDoer

        """
        self.hby = hby
        self.rgy = rgy
        self.mbx = mbx
        self.controller = controller
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        doers = [doing.doify(self.msgDo)]

        super(IssueHandler, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth, tock=0.0):
        """ Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload (dict): representing the body of a /credential/issue message
            pre (qb64): identifier prefix of sender
            sigers (list): of Sigers representing the sigs on the /credential/issue message
            verfers (list): of Verfers of the keys used to sign the message

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]

                if "i" not in payload or "s" not in payload or "a" not in payload:
                    logger.error(f"invalid credential issuance message, i, s and a are required fields.  evt=: "
                                 f"{payload}")
                    continue

                iaid = payload["i"]
                ssaid = payload["s"]
                csaid = payload["a"]

                data = dict(
                    r='/credential/issue',
                    issuer=dict(
                        i=iaid
                    ),
                    schema=dict(
                        d=ssaid
                    ),
                    credential=dict(
                        d=csaid
                    )
                )

                creder = self.rgy.reger.creds.get(csaid)
                if creder is not None:
                    data["credential"]["sad"] = creder.crd

                # TODO:  Get schema resolver and Organizer to load schema and contact info if any.
                raw = json.dumps(data).encode("utf-8")

                if self.controller is not None:
                    self.mbx.storeMsg(self.controller+"/credential", raw)

                yield self.tock

            yield self.tock


def credentialIssueExn(hab, schema, said):
    """

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        schema (str): qb64 SAID of JSON schema of credential being issued
        said (str): qb64 SAID of credentiual being issued

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        c=said,
    )

    exn = exchanging.exchange(route="/credential/issue", payload=data)
    ims = hab.endorse(serder=exn, last=True, pipelined=False)
    del ims[:exn.size]

    return exn, ims


class PresentationRequestHandler(doing.Doer):
    """ Processor for a presentation request

        Processor for a credential request with input descriptors in the payload used to
        match saved credentials based on a schema.  The payload of the request is expected to
        have the following format:

             {
                ""submission_requirements": [{
                   "name": "Proof of LEI",
                   "rule": "pick",
                   "count": 1,
                   "from": "A"
                 }]
                "input_descriptors": [
                   {
                      "x":"EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA",
                      "group": ["A"],
                   }
                ],
                "format": {
                   "cesr": {
                     "proof_type": ["Ed25519Signature2018"]
                   }
                }
             }

    """

    resource = "/presentation/request"

    def __init__(self, hby, wallet, cues=None, **kwa):
        """ Create an `exn` request handler for processing credential presentation requests

        Parameters
            hab (Habitat): is the environment
            wallet (Wallet): is the wallet holding the credentials to present
            cues (Optional(decking.Deck)): outbound response cue for  this handler

        """
        self.hby = hby
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.wallet = wallet

        super(PresentationRequestHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Process presentation request message with sender identifier, sigs and verfers

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload (dict): representing the body of a /presentation/request message
            pre (qb64): identifier prefix of sender
            sigers (list): of Sigers representing the sigs on the /presentation/request message
            verfers (list): of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                requestor = msg["pre"]
                descriptors = payload["input_descriptors"]

                matches = []
                for descriptor in descriptors:
                    schema = descriptor["s"]
                    credentials = self.wallet.getCredentials(schema)
                    if len(credentials) > 0:
                        matches.append(credentials[0])

                if len(matches) > 0:
                    pe = presentationExchangeExn(db=self.hby.db, reger=self.wallet.reger, credentials=matches)
                    exn = exchanging.exchange(route="/presentation/proof", payload=pe)
                    self.cues.append(dict(dest=requestor.qb64, rep=exn, topic="credential"))

                yield

            yield


class PresentationProofHandler(doing.Doer):
    """ Processor for responding to presentation proof peer to peer message.

      The payload of the message is expected to have the following format:

        {
          "presentation_submission": {
              "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
              "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
              "descriptor_map": [
                   {
                     "id": "gleif_vlei",
                     "format": "cesr",
                     "path": "$.verifiableCredential[0]"
                   }
              ]
          },
          "verifiableCredential": [
              {
                "vc": {
                   "v": "KERI10JSON00011c_", //KERI Version String
                   "x": "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI", // Identifier prefix of the Schema
                   "q": {
                        "type": [
                            "EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI"
                        ],
                        "id": "did:keri:EeyJ0eXBlIjogWyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI",
                        "issuer": "did:keri:EchZLZUFqtBGRWMh3Ur_iKucjsrFcxU7AjfCPko9CkEA",  //Identifier prefix of
                        the issuer
                        "issuanceDate": "2021-06-09T17:35:54.169967+00:00",
                        "credentialSubject": {
                            "id": "did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",
                            "lei": "254900OPPU84GM83MG36"
                        }
                    } // embedded verifiable credential
                }
                "proof": "-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE
                -YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI
                -AABAALK_6pkUjCx76CTE7pNrKlhC84ewgZbs-4ciTvLcxkwUaWX7ukpr55P9RtJhlHxdtz3kN0zfM0HrtFitKuPy3BA"
              }
           ]
        }
    """

    resource = "/presentation/proof"

    def __init__(self, cues=None, proofs=None, **kwa):
        """ Initialize instance

        Parameters:
            cues (decking.Deck): outbound cue messages
            proofs (decking.Deck): inbound proof request `exn` messages
            **kwa (dict): keyword arguments passes to super Doer

        """
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.proofs = proofs if proofs is not None else decking.Deck()

        super(PresentationProofHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Handle incoming messages by parsing and verifying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message


        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                pre = msg["pre"]

                if "presentation_submission" not in payload:
                    raise ValueError("invalid presentation proof payload")

                if "verifiableCredential" not in payload:
                    raise ValueError("invalid presentation proof payload")

                pe = payload["presentation_submission"]
                vcs = payload["verifiableCredential"]

                if "descriptor_map" not in pe:
                    raise ValueError("invalud presentation submission in proof payload")

                # TODO:  Find verifiable credential in vcs based on `path`
                dm = pe["descriptor_map"]
                print(dm)

                vcs.reverse()
                for vc in vcs:
                    self.proofs.append((pre, vc))

                yield

            yield


def presentationExchangeExn(db, reger, credentials):
    """ Create a presentation exchange.

    Create presentation exchange body containing the credential and event logs
    needed to provide proof of holding a valid credential

    Parameters:
        db (Baser): is the environment database
        reger (Registry): is the credential registry database
        credentials (list): is the list of credential instances

    Returns:
        dict: presentation dict for credential

    """
    dm = []
    vcs = []

    for idx, (creder, sadsigers, sadcigars) in enumerate(credentials):
        said = creder.said
        regk = creder.status

        issr = creder.crd["i"]

        msgs = bytearray()
        for msg in db.clonePreIter(pre=issr):
            msgs.extend(msg)

        for msg in reger.clonePreIter(pre=regk):
            msgs.extend(msg)

        for msg in reger.clonePreIter(pre=said):
            msgs.extend(msg)

        dm.append(dict(
            id=creder.schema,
            format="cesr",
            path="$.verifiableCredential[{}]".format(idx)
        ))

        craw = signing.provision(creder, sadsigers=sadsigers, sadcigars=sadcigars)
        vcs.append(creder.said)

        sources = reger.sources(db, creder)
        vcs.extend([creder.said for creder, msgs in sources])

    d = dict(
        presentation_submission=dict(
            descriptor_map=dm
        ),
        verifiableCredential=vcs,
    )

    return d
