import argparse
import os
import os.path

import falcon
from hio import help
from hio.core.uxd import Server, ServerDoer
from hio.help import decking

from keri import kering
from hio.help import Hict
from keri.end import ending
from keri.help import helping
from keri.app import habbing, directing
from keri.app.cli.common import existing
class SignHandler:
    resource = "/sign"

    def __init__(self, cues, base):
        """ Initialize peer to peer challenge response messsage """

        self.cues = cues
        self.base = base
        super(SignHandler, self).__init__()

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of Challenge response messages

        Parameters:
            serder (Serder): Serder of the exn challenge response message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event
        """
        # print(serder.ked)
        payload = serder.ked['a']

        name = payload["name"]
        passcode = payload["passcode"] if "passcode" in payload else None
        method = payload["method"] if "method" in payload else None
        data = payload["data"] if "data" in payload else None
        path = payload["path"] if "path" in payload else None
        signator = payload["signator"] if "signator" in payload else None

        print(data)
        try:
            hby = habbing.Habery(name=name, base=self.base, bran=passcode)
            for hab in hby.habs.values():
                aid = hab.pre
                if hab.name == signator:
                    try:
                        auth = Authenticator(path=path, name=signator, aid=aid, method=method, hab=hab)
                    except Exception as err:
                        print(err)
                    headers = auth.sign()


            hby.close()
            self.cues.append(dict(status=falcon.HTTP_200, body=headers))
        except (kering.AuthError, ValueError) as e:
            msg = dict(status=falcon.HTTP_400, body=str(e))
            self.cues.append(msg)
class IdentifiersHandler:
    """  Handle challenge response peer to peer `exn` message """

    resource = "/identifiers"

    def __init__(self, cues, base):
        """ Initialize peer to peer challenge response messsage """

        self.cues = cues
        self.base = base
        super(IdentifiersHandler, self).__init__()

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of Challenge response messages

        Parameters:
            serder (Serder): Serder of the exn challenge response message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        payload = serder.ked['a']
        name = payload["name"]
        passcode = payload["passcode"] if "passcode" in payload else None

        try:
            hby = habbing.Habery(name=name, base=self.base, bran=passcode)
            print("habs")
            identifiers = []
            for hab in hby.habs.values():
                msg = dict(name=hab.name, prefix=hab.pre)
                identifiers.append(msg)

            hby.close()
            self.cues.append(dict(status=falcon.HTTP_200, body=identifiers))
        except (kering.AuthError, ValueError) as e:
            msg = dict(status=falcon.HTTP_400, body=str(e))
            self.cues.append(msg)


class UnlockHandler:
    """  Handle challenge response peer to peer `exn` message """

    resource = "/unlock"

    def __init__(self, cues, base):
        """ Initialize peer to peer challenge response messsage """

        self.cues = cues
        self.base = base
        super(UnlockHandler, self).__init__()

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of Challenge response messages

        Parameters:
            serder (Serder): Serder of the exn challenge response message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        payload = serder.ked['a']
        name = payload["name"]
        passcode = payload["passcode"] if "passcode" in payload else None

        try:
            hby = habbing.Habery(name=name, base=self.base, bran=passcode, free=True)
            print("unlocked")
            msg = dict(status=falcon.HTTP_200, body={})
            hby.close()

        except (kering.AuthError, ValueError) as e:
            msg = dict(status=falcon.HTTP_400, body=str(e))

        self.cues.append(msg)

class Authenticator:
    def __init__(self, path, name, aid, method, hab):
        self.path = path
        self.name = name
        self.aid = aid
        self.method = method
        self.hab = hab
        self.default_fields = ["Signify-Resource",
                               "@method",
                               "@path",
                               "Signify-Timestamp"]
    @staticmethod
    def resource(response):
        headers = response.headers
        if "SIGNIFY-RESOURCE" not in headers:
            raise kering.AuthNError("SIGNIFY-RESOURCE not found in header.")
        return headers["SIGNIFY-RESOURCE"]

    def sign(self):
        headers = Hict([
            ("Content-Type", "application/json"),
            ("Content-Length", "256"),
            ("Connection", "close"),
            ("Signify-Resource", self.aid),
            ("Signify-Timestamp", helping.nowIso8601()),
        ])
        if self.method == "DELETE" or self.method == "GET":
            headers = Hict([
                ("Connection", "close"),
                ("Signify-Resource", self.aid),
                ("Signify-Timestamp", helping.nowIso8601()),
            ])
        header, qsig = ending.siginput("signify", method=self.method, path=self.path, headers=headers, fields=self.default_fields,
                                       hab=self.hab, alg="ed25519", keyid=self.aid)
        headers.extend(header)
        signage = ending.Signage(markers=dict(signify=qsig), indexed=False, signer=None, ordinal=None, digest=None,
                                 kind=None)
        headers.extend(ending.signature([signage]))

        return dict(headers)

    def verify(self, response):
        headers = response.headers

        if "SIGNATURE-INPUT" not in headers or "SIGNATURE" not in headers:
            return False

        siginput = headers["SIGNATURE-INPUT"]
        if not siginput:
            return False
        signature = headers["SIGNATURE"]
        if not signature:
            return False

        inputs = ending.desiginput(siginput.encode("utf-8"))
        inputs = [i for i in inputs if i.name == "signify"]

        if not inputs:
            return False

        for inputage in inputs:
            items = []
            for field in inputage.fields:
                key = field.upper()
                field = field.lower()
                if key not in headers:
                    continue

                value = ending.normalize(headers[key])
                items.append(f'"{field}": {value}')

            values = [f"({' '.join(inputage.fields)})", f"created={inputage.created}"]
            if inputage.expires is not None:
                values.append(f"expires={inputage.expires}")
            if inputage.nonce is not None:
                values.append(f"nonce={inputage.nonce}")
            if inputage.keyid is not None:
                values.append(f"keyid={inputage.keyid}")
            if inputage.context is not None:
                values.append(f"context={inputage.context}")
            if inputage.alg is not None:
                values.append(f"alg={inputage.alg}")

            params = ';'.join(values)

            items.append(f'"@signature-params: {params}"')
            ser = "\n".join(items).encode("utf-8")

            resource = self.resource(response)

            with habbing.openHab(name="hkapi", temp=False) as (hkHby, hkHab):
                if resource not in hkHab.kevers:
                    raise kering.AuthNError("unknown or invalid controller")

                ckever = hkHab.kevers[resource]
                signages = ending.designature(signature)
                cig = signages[0].markers[inputage.name]
                if not ckever.verfers[0].verify(sig=cig.raw, ser=ser):
                    raise kering.AuthNError(f"Signature for {inputage} invalid")

        return True