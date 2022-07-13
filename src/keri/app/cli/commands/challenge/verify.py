# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import datetime
import json
import sys

from hio import help
from hio.base import doing

from keri.app import indirecting, challenging, storing, connecting
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
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument('--words', '-d', help='JSON formatted array of words to sign, \'@\' allowed to load from a file',
                    action="store", required=True)
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
                    signer=args.signer)
    return [ld]


class VerifyDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, words, signer):

        self.wordstr = words
        self.words = words.split(" ")
        self.signer = signer
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        self.org = connecting.Organizer(hby=self.hby)
        self.mbx = storing.Mailboxer(name=name)
        self.mbx.reopen()

        challenging.loadHandlers(hby=self.hby, exc=self.exc, mbx=self.mbx, controller=self.hab.pre)

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=['/challenge'], exc=self.exc)

        doers = [self.mbd, self.exc, doing.doify(self.verifyDo)]

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

        end = helping.nowUTC() + datetime.timedelta(seconds=5)
        sys.stdout.write(f"Checking mailboxes for any challenge responses")
        sys.stdout.flush()
        while helping.nowUTC() < end:
            sys.stdout.write(".")
            sys.stdout.flush()
            if "/challenge" in self.mbd.times:
                end = self.mbd.times['/challenge'] + datetime.timedelta(seconds=5)
            yield 1.0
        print("\n")

        actual = self.mbx.getTopicMsgs(topic=f"{self.hab.pre}/challenge")
        found = False
        for msg in actual:
            data = json.loads(msg)
            if data["signer"] == sig and data["words"] == self.words:
                found = True
                break

        if found:
            print(f"Signer {self.signer} successfully responded to challenge words: {self.wordstr}")
        else:
            print(f"No response found from {self.signer}")

        print()
        self.remove([self.mbd, self.exc])
