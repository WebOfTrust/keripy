# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json

import pysodium
from hio import help
from hio.base import doing
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

from keri import kering
from keri.app import grouping, indirecting, forwarding, connecting
from keri.app.agenting import WitnessPublisher
from keri.app.cli.common import existing
from keri.app.notifying import Notifier
from keri.core import coring, scheming
from keri.peer import exchanging
from keri.vc import proving
from keri.vdr import viring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Encrypt Sender-key Sign Receiver-key HTTP gateway utility.')
parser.set_defaults(handler=lambda args: send(args),
                    transferable=True)
parser.add_argument('url', metavar='<url>', type=str,
                    help='URL to request')
parser.add_argument('--name', '-n', help='Keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='Additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='Human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--recipient", "-r", help="Alias or qb64 identifier prefix of the self.recp of "
                                              "the credential", required=True)

parser.add_argument("--time", help="Timestamp for the essr send message (used for debugging)",
                    required=False, default=None)
parser.add_argument('--request', '-X', dest="method", help='Specify request method to use', default=None,
                    action="store", required=False)
parser.add_argument('--data', '-d', help='HTTP POST data, \'@\' allowed', default=None, action="store", required=False)
parser.add_argument('--header', '-H', help='Pass custom header(s) to server', metavar="<header/@file>", default=None,
                    action="append", required=False)

HTTP_SCHEMA = "EM9BOwcHae1PWPioc5K2gtoElgoiKL7J_X89bfbdshjn"


def send(args):
    """ Command line tool for adding endpoint role authorizations
    """
    if args.data is None:
        data = None
    elif args.data.startswith("@"):
        f = open(args.data[1:], "r")
        data = f.read()
    else:
        data = args.data

    ld = ESSRDoer(name=args.name,
                  base=args.base,
                  alias=args.alias,
                  bran=args.bran,
                  url=args.url,
                  recp=args.recipient,
                  timestamp=args.time,
                  headers=args.header,
                  data=data,
                  method=args.method)

    return [ld]


class ESSRDoer(doing.DoDoer):

    def __init__(self, name, base, alias, bran, url, recp, headers=None, timestamp=None, data=None, method="GET"):
        self.url = url
        self.method = method
        self.recp = recp
        self.timestamp = timestamp
        self.data = data
        self.headers = headers if headers is not None else []

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.reger = viring.Reger(name=self.hby.name, temp=self.hby.temp)
        self.hab = self.hby.habByName(alias)
        self.witpub = WitnessPublisher(hby=self.hby)
        self.org = connecting.Organizer(hby=self.hby)
        notifier = Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=self.hby, handlers=[ESSRResponseHandler(hby=self.hby, reger=self.reger)])
        grouping.loadHandlers(exc, mux)

        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/replay"], exc=exc)

        if self.hab is None:
            raise kering.ConfigurationError(f"unknown alias={alias}")

        self.toRemove = [self.witpub, self.mbx]

        super(ESSRDoer, self).__init__(doers=self.toRemove + [doing.doify(self.sendDo)])

    def sendDo(self, tymth, tock=0.0):
        """ Export any end reply messages previous saved for the provided AID

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

        if self.recp in self.hby.kevers:
            recp = self.recp
        else:
            recp = self.org.find("alias", self.recp)
            if len(recp) != 1:
                raise ValueError(f"invalid recipient {self.recp}")
            recp = recp[0]['id']

        if recp is None:
            raise ValueError("unable to find recipient")

        if self.method is None:
            self.method = "POST" if self.data is not None else "GET"

        h = headers(self.headers)

        if "Accept" not in h:
            h["Accept"] = "*/*"

        payload = dict(
            method=self.method,
            url=self.url,
            version="HTTP 1.1",
            headers=h,
            body=''
        )

        if self.data is not None:
            try:
                data = json.loads(self.data)
                payload['body'] = data

                if "Content-Length" not in h:
                    h["Content-Length"] = str(len(self.data))

            except json.JSONDecodeError:
                raise kering.ConfigurationError("only JSON data accepted currently")

        creder = proving.credential(schema="EM9BOwcHae1PWPioc5K2gtoElgoiKL7J_X89bfbdshjn",
                                    issuer=self.hab.pre,
                                    data=payload,
                                    recipient=recp)
        msg = creder.raw

        # convert signing public key to encryption public key
        rkever = self.hby.kevers[recp]
        pubkey = pysodium.crypto_sign_pk_to_box_pk(rkever.verfers[0].raw)
        raw = pysodium.crypto_box_seal(bytes(msg), pubkey)
        b64 = encodeB64(raw)
        bexter = coring.Bexter(raw=b64)

        x, _ = exchanging.exchange(route="/essr/req",
                                   payload=dict(d=bexter.qb64),
                                   sender=self.hab.pre,
                                   recipient=recp,
                                   date=self.timestamp)
        ims = self.hab.endorse(serder=x, pipelined=False)
        atc = ims[x.size:]

        postman = forwarding.StreamPoster(hby=self.hby, hab=self.hab, recp=recp, headers={
            "Message-SAID": x.said,
        })

        postman.send(serder=x,
                     attachment=atc)

        doer = doing.DoDoer(doers=postman.deliver())
        self.extend([doer])

        while not doer.done:
            yield self.tock

        messager = doer.doers[0]
        self.mbx.parser.parse(bytes(messager.rep.body))

        self.remove(self.toRemove)
        return


def headers(x):
    return dict([[i.strip().strip(r"'-H \$'") for i in
                  [h.split(': ')[0], ': '.join(h.split(': ')[1:])]] for h in x])


class ESSRResponseHandler:
    """
    Handler for multisig coordination EXN messages

    """
    resource = "/essr/rep"

    def __init__(self, hby, reger):
        """ Create an exn handler for multisig messages

        Parameters:
            hby (Habery): database environment for gateway AIDs
            reger (Reger): verification specific database
        """
        self.hby = hby
        self.reger = reger
        self.resolver = scheming.CacheResolver(db=hby.db)

    def verify(self, serder, attachments=None):
        """

        Parameters:
            serder:
            attachments:

        Returns:

        """
        aid = serder.ked['i']
        if aid not in self.hby.kevers:
            print(f"unknown AID={aid} sending event")
            return False

        pay = serder.ked['a']
        recp = pay['i']

        if recp not in self.hby.habs:
            print(f"invalid target AID={aid}")
            return False

        hab = self.hby.habs[recp]
        bexter = coring.Bexter(qb64=pay['d'])
        raw = hab.decrypt(decodeB64(bexter.raw))

        try:
            creder = proving.Creder(raw=raw)
        except ValueError:
            print("Invalid encrypted credential")
            return False

        # Verify the credential against the schema
        if HTTP_SCHEMA != creder.schema:
            print(f"schema {creder.schema} not valid for credential {creder.said}")
            return False

        scraw = self.resolver.resolve(HTTP_SCHEMA)
        schemer = scheming.Schemer(raw=scraw)
        try:
            schemer.verify(creder.raw)
        except kering.ValidationError as ex:
            print("Credential {} is not valid against schema {}: {}"
                  .format(creder.said, creder.schema, ex))
            return False

        self.reger.creds.pin(keys=(serder.said,), val=creder)

        return True

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of multisig exn messages

        Parameters:
            serder (Serder): Serder of the exn multisig message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        creder = self.reger.creds.get(keys=(serder.said,))
        pay = creder.ked['a']

        body = pay["body"]

        print(json.dumps(body))

