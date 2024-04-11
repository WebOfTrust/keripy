# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri.app import habbing, forwarding, connecting
from keri.app.cli.common import existing
from keri.app.habbing import GroupHab
from keri.peer import exchanging

parser = argparse.ArgumentParser(description='Respond to a list of challenge words by signing and sending an EXN '
                                             'response')
parser.set_defaults(handler=lambda args: respond(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--words', '-d', help='JSON formatted array of words to sign, \'@\' allowed to load from a file',
                    action="store", required=True)
parser.add_argument('--recipient', '-r', help='Contact alias of the AID to send the signed words to',
                    action="store", required=True)


def respond(args):
    """
    Performs a rotation of the identifier of the environment represented by the provided name parameter

        args (parseargs):  Command line argument

    """
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran
    recp = args.recipient

    if args.words.startswith("@"):
        f = open(args.data[1:], "r")
        words = f.read()
    else:
        words = args.words

    words = words.split(" ")
    if not isinstance(words, list):
        raise ValueError("words must be an array of words")

    ixnDoer = RespondDoer(name=name, base=base, alias=alias, bran=bran, words=words, recp=recp)

    return [ixnDoer]


class RespondDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to create an interaction event and publication of the event
    to all appropriate witnesses
    """

    def __init__(self, name, base, bran, alias, words: list, recp: str):
        """
        Returns DoDoer with all registered Doers needed to perform interaction event.

        Parameters:
            name is human readable str of identifier
            proto is tcp or http method for communicating with Witness
            data is list of dicts of committed data such as seals
       """

        self.alias = alias
        self.words = words
        self.recp = recp

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.postman = forwarding.Poster(hby=self.hby)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.org = connecting.Organizer(hby=self.hby)
        doers = [self.hbyDoer, self.postman, doing.doify(self.respondDo)]

        super(RespondDoer, self).__init__(doers=doers)

    def respondDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.alias is None:
            self.alias = existing.aliasInput(self.hby)

        hab = self.hby.habByName(name=self.alias)
        if hab is None:
            raise ValueError(f"invalid alias {self.alias}")

        recp = self.org.find("alias", self.recp)
        if len(recp) != 1:
            raise ValueError(f"invalid recipient {self.recp}")

        recp = recp[0]['id']

        payload = dict(i=hab.pre, words=self.words)
        exn, _ = exchanging.exchange(route="/challenge/response", payload=payload, sender=hab.pre)
        ims = hab.endorse(serder=exn, last=False, pipelined=False)
        del ims[:exn.size]

        senderHab = hab.mhab if isinstance(hab, GroupHab) else hab
        self.postman.send(src=senderHab.pre, dest=recp, topic="challenge", serder=exn, attachment=ims)
        while not self.postman.cues:
            yield self.tock

        toRemove = [self.hbyDoer, self.postman]
        self.remove(toRemove)

        return
