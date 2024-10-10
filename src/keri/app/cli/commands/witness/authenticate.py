# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json
import sys

import qrcode
from hio import help
from hio.base import doing
from hio.help import Hict

from keri.app import httping, connecting
from keri.app.agenting import httpClient
from keri.app.cli.common import existing
from keri.app.httping import CESR_DESTINATION_HEADER
from keri.core import coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Perform authentication against an witness to get a OTP code')
parser.set_defaults(handler=lambda args: auth(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
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
        self.org = connecting.Organizer(hby=self.hby)
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

    def authDo(self, tymth, tock=0.0):
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
