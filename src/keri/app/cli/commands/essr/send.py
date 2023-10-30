# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

import pysodium
from hio import help
from hio.base import doing
from base64 import urlsafe_b64encode as encodeB64

from keri import kering
from keri.app import grouping, indirecting, forwarding, connecting, signing
from keri.app.agenting import WitnessPublisher
from keri.app.cli.common import existing
from keri.app.notifying import Notifier
from keri.core import coring
from keri.peer import exchanging
from keri.vc import proving, protocoling

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Encrypt Sender-key Sign Receiver-key send utility.')
parser.set_defaults(handler=lambda args: send(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--recipient", "-r", help="alias or qb64 identifier prefix of the self.recp of "
                                              "the credential", required=True)

parser.add_argument("--time", help="timestamp for the essr send message (used for debugging)",
                    required=False, default=None)


def send(args):
    """ Command line tool for adding endpoint role authorizations

    """
    ld = ESSRDoer(name=args.name,
                  base=args.base,
                  alias=args.alias,
                  bran=args.bran,
                  recp=args.recipient,
                  timestamp=args.time)
    return [ld]


class ESSRDoer(doing.DoDoer):

    def __init__(self, name, base, alias, bran, recp, timestamp=None):
        self.recp = recp
        self.timestamp = timestamp

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.witpub = WitnessPublisher(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby)
        self.org = connecting.Organizer(hby=self.hby)
        notifier = Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(exc, mux)

        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/replay"], exc=exc)

        if self.hab is None:
            raise kering.ConfigurationError(f"unknown alias={alias}")

        self.toRemove = [self.witpub, self.postman, mbx]

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

        creder = proving.credential(schema="EM9BOwcHae1PWPioc5K2gtoElgoiKL7J_X89bfbdshjn",
                                    issuer=self.hab.pre,
                                    data=dict(patientId="ABC123", diagnosis="Very Sick"),
                                    recipient=recp)

        print(creder.pretty())
        msg = creder.raw

        # convert signing public key to encryption public key
        recp = self.hby.kevers[recp]
        pubkey = pysodium.crypto_sign_pk_to_box_pk(recp.verfers[0].raw)
        raw = pysodium.crypto_box_seal(bytes(msg), pubkey)
        b64 = encodeB64(raw)
        bexter = coring.Bexter(raw=b64)

        print("Encrypted ACDC")
        print(bexter.qb64)

        print("Digest of Encrypted material")
        diger = coring.Diger(ser=bexter.qb2)
        print(diger.qb64)


        ser = f'{recp.verfers[0].qb64}:{diger.qb64}'.encode("utf-8")
        sigers = self.hab.sign(ser)

        print(f"Signed {ser}:")
        print(f"\t{sigers[0].qb64}")

        x, _ = exchanging.exchange(route="/essr/send",
                                   payload=dict(d=diger.qb64),
                                   sender=self.hab.pre,
                                   recipient=recp.serder.pre,
                                   date=self.timestamp)

        self.remove(self.toRemove)
        return
