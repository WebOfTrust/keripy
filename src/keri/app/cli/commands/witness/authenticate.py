# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json

import qrcode
from hio.base import doing
from hio.help import Hict

from ..... import help
from .... import httping, organizing
from ....agenting import httpClient
from ...common import existing
from ...common.parsing import Parsery
from ....httping import CESR_DESTINATION_HEADER
from .....core import coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Perform authentication against an witness to get a OTP code', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: auth(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument("--witness", '-w', help="the witness AID or alias to authenticate against", required=True)
parser.add_argument("--url-only", '-u', dest="url", help="display only the URL (no QR Code).", required=False,
                    action="store_true")


def auth(args):
    """ Command line handler for authenticating  against a witness by retrieving the secret or a TOTP

    Parameters:
        args(Namespace): parsed command line arguments

    """

    ed = AuthDoer(name=args.name,
                  alias=args.alias,
                  base=args.base,
                  bran=args.bran,
                  witness=args.witness,
                  urlOnly=args.url)
    return [ed]


class AuthDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, witness, urlOnly):
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.org = organizing.Organizer(hby=self.hby)
        self.urlOnly = urlOnly

        if witness in self.hby.kevers:
            wit = witness
        else:
            wit = self.org.find("alias", witness)
            if len(wit) != 1:
                raise ValueError(f"invalid recipient {witness}")
            wit = wit[0]['id']

        if not wit:
            raise ValueError(f"unknown witness {witness}")

        self.witness = wit
        self.clienter = httping.Clienter()
        doers = [doing.doify(self.authDo), self.clienter]

        super(AuthDoer, self).__init__(doers=doers)

    def authDo(self, tymth, tock=0.0, **kwa):
        """ Export credential from store and any related material

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        body = bytearray()
        for msg in self.hab.db.clonePreIter(pre=self.hab.pre):
            body.extend(msg)

        fargs = dict([("kel", body.decode("utf-8"))])

        if self.hab.kever.delegated:
            delkel = bytearray()
            for msg in self.hab.db.clonePreIter(self.hab.kever.delpre):
                delkel.extend(msg)

            fargs['delkel'] = delkel.decode("utf-8")

        headers = (Hict([
            ("Content-Type", "multipart/form-data"),
            (CESR_DESTINATION_HEADER, self.witness)
        ]))

        client, clientDoer = httpClient(self.hab, self.witness)
        self.extend([clientDoer])

        client.request(
            method="POST",
            path=f"{client.requester.path}/aids",
            headers=headers,
            fargs=fargs
        )
        while not client.responses:
            yield self.tock

        rep = client.respond()
        if rep.status == 200:
            data = json.loads(rep.body)

            totp = data["totp"]
            m = coring.Matter(qb64=totp)  # refactor this to use cipher
            d = coring.Matter(qb64=self.hab.decrypt(ser=m.raw))
            otpurl = f"otpauth://totp/KERIpy:{self.witness}?secret={d.raw.decode('utf-8')}&issuer=KERIpy"

            if not self.urlOnly:
                qr = qrcode.QRCode()
                qr.add_data(otpurl)

                qr.print_ascii()

            print(otpurl)

        else:
            raise ValueError(rep.body)

        self.remove([clientDoer, self.clienter])
