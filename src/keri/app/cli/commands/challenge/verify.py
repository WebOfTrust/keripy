# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import datetime
import sys

from hio import help
from hio.base import doing

from keri.app import indirecting, challenging, connecting, signaling
from keri.app.cli.commands.challenge.generate import generateWords
from keri.app.cli.common import existing
from keri.help import helping
from keri.peer import exchanging

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Check mailbox for EXN challenge response messages and verify their '
                                             'signatures and data against provided words and signer')
parser.set_defaults(handler=lambda args: verify(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    default=None)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument('--words', '-d', help='JSON formatted array of words to verfiy, \'@\' allowed to load from a file',
                    action="store", required=False)
parser.add_argument('--generate', '-g', help="Generate words, print to stdout and wait for verification",
                    action="store_true")
parser.add_argument('--strength', help='Cryptographic strength in bits.  Defaults to 128.  Only applies with '
                                       '--generate', default=128, required=False)
parser.add_argument("--out", "-o", help="Output type [words|string|json] of phrase.  Default is json.  Only applies "
                                        "with --generate", choices=["words", "string", "json"], default="json",
                    required=False)

parser.add_argument('--signer', '-s', help='Contact alias of the AID to verify',
                    action="store", required=True)


def verify(args):
    """ Command line list credential registries handler

    """
    ld = VerifyDoer(name=args.name,
                    alias=args.alias,
                    base=args.base,
                    bran=args.bran,
                    words=args.words,
                    generate=args.generate,
                    strength=args.strength,
                    out=args.out,
                    signer=args.signer)
    return [ld]


class VerifyDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, words, generate, strength, out, signer):

        self.wordstr = words
        self.words = words
        self.generate = generate
        self.strength = strength
        self.out = out
        self.signer = signer
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        if alias is None:
            alias = existing.aliasInput(self.hby)

        self.hab = self.hby.habByName(alias)
        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        self.org = connecting.Organizer(hby=self.hby)
        signaler = signaling.Signaler()

        challenging.loadHandlers(db=self.hby.db, signaler=signaler, exc=self.exc)

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=['/challenge'], exc=self.exc)

        doers = [self.mbd, doing.doify(self.verifyDo)]

        super(VerifyDoer, self).__init__(doers=doers)

    def verifyDo(self, tymth, tock=0.0):
        """ Check for any credential messages in mailboxes and list all held credentials

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

        if self.signer in self.hby.kevers:
            sig = self.signer
        else:
            sig = self.org.find("alias", self.signer)
            if len(sig) != 1:
                raise ValueError(f"invalid signer {self.signer}")
            sig = sig[0]['id']

        if self.generate:
            words = generateWords(self.strength, self.out)
        else:
            words = self.words.split(" ")

        end = helping.nowUTC() + datetime.timedelta(seconds=300)
        sys.stdout.write(f"Checking mailboxes for any challenge responses")
        sys.stdout.flush()
        found = False
        while helping.nowUTC() < end:
            sys.stdout.write(".")
            sys.stdout.flush()

            saiders = self.hby.db.reps.get(keys=(sig,))
            for saider in saiders:
                exn = self.hby.db.exns.get(keys=(saider.qb64,))
                if words == exn.ked['a']['words']:
                    found = True
                    self.hby.db.chas.add(keys=(sig,), val=saider)
                    break

            if found:
                break

            yield 2.0
        print("\n")

        if found:
            print(f"Signer {self.signer} successfully responded to challenge words: '{words}'")
        else:
            print(f"No response found from {self.signer}")

        print()
        self.remove([self.mbd, self.exc])
