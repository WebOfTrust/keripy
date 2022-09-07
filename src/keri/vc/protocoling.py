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
               "s": "EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs",
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

    def __init__(self, hby, rgy, notifier, **kwa):
        """ Initialize instance

        Parameters:
            hab (Habitat): local identifier environment
            wallet (Wallet) credential wallet that will hold the issued credentials
            ims (Optional(bytearray)): inbound message stream to process
            notifier (Notifier): outbound notifications
            **kwa (dict): keyword arguments passed to DoDoer

        """
        self.hby = hby
        self.rgy = rgy
        self.notifier = notifier
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
                    print(f"invalid credential issuance message, i, s and a are required fields.  evt=: "
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
                self.notifier.add(attrs=data)
                yield self.tock

            yield self.tock


def credentialIssueExn(hab, issuer, schema, said):
    """

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        issuer (str): qb64 AID of the issuer of the credential
        schema (str): qb64 SAID of JSON schema of credential being issued
        said (str): qb64 SAID of credentiual being issued

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        i=issuer,
        s=schema,
        a=said,
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

    def __init__(self, hby, notifier, cues=None, **kwa):
        """ Create an `exn` request handler for processing credential presentation requests

        Parameters
            hab (Habitat): is the environment
            wallet (Wallet): is the wallet holding the credentials to present
            cues (Optional(decking.Deck)): outbound response cue for  this handler

        """
        self.hby = hby
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.notifier = notifier

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
                if "i" not in payload and "s" not in payload and "n" not in payload:
                    print(f"invalid credential request message, one of i, s and n are required fields.  evt=: "
                          f"{payload}")
                    continue

                data = dict(
                    r='/presentation/request',
                    issuer={},
                    schema={},
                    credential={}
                )

                if "i" in payload:
                    data["issuer"] = dict(
                        i=payload["i"]
                    )
                if "s" in payload:
                    data["schema"] = dict(
                        n=payload["s"]
                    )
                if "i" in payload:
                    data["credential"] = dict(
                        n=payload["n"]
                    )

                self.notifier.add(attrs=data)

                yield self.tock

            yield self.tock


class PresentationProofHandler(doing.Doer):
    """ Processor for responding to presentation proof peer to peer message.

      The payload of the message is expected to have the following format:

    """

    resource = "/presentation"

    def __init__(self, notifier, cues=None, **kwa):
        """ Initialize instance

        Parameters:
            cues (decking.Deck): outbound cue messages
            proofs (decking.Deck): inbound proof request `exn` messages
            **kwa (dict): keyword arguments passes to super Doer

        """
        self.msgs = decking.Deck()
        self.notifier = notifier
        self.cues = cues if cues is not None else decking.Deck()

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

                if "i" not in payload or "s" not in payload or "n" not in payload:
                    print(f"invalid credential presentation message, i, s and n are required fields.  evt=: "
                          f"{payload}")
                    continue

                iaid = payload["i"]
                ssaid = payload["s"]
                csaid = payload["n"]

                data = dict(
                    r='/presentation',
                    issuer=dict(
                        i=iaid
                    ),
                    schema=dict(
                        n=ssaid
                    ),
                    credential=dict(
                        n=csaid
                    )
                )
                self.notifier.add(attrs=data)
            yield


def presentationExchangeExn(hab, reger, said):
    """ Create a presentation exchange.

    Create presentation exchange body containing the credential and event logs
    needed to provide proof of holding a valid credential

    Parameters:
        hab (Hab): is the environment database
        reger (Registry): is the credential registry database
        said (str): qb64 SAID of the credential to present

    Returns:
        dict: presentation dict for credential

    """
    creder = reger.creds.get(said)
    if creder is None:
        raise ValueError(f"unable to find credential {said} to present")

    data = dict(
        i=creder.issuer,
        s=creder.schema,
        n=said,
    )

    exn = exchanging.exchange(route="/presentation", payload=data)
    ims = hab.endorse(serder=exn, last=True, pipelined=False)
    del ims[:exn.size]

    return exn, ims
