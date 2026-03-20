# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from ...common import Parsery, setupHby, aliasInput

from ....app import Poster, Organizer, GroupHab, HaberyDoer
from ....peer import exchange


parser = argparse.ArgumentParser(description='Respond to a list of challenge words by signing and sending an EXN '
                                             'response',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: respond(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to use for responding', default=None)
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

        self.hby = setupHby(name=name, base=base, bran=bran)
        self.postman = Poster(hby=self.hby)
        self.hbyDoer = HaberyDoer(habery=self.hby)  # setup doer
        self.org = Organizer(hby=self.hby)
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
            self.alias = aliasInput(self.hby)

        hab = self.hby.habByName(name=self.alias)
        if hab is None:
            raise ValueError(f"invalid alias {self.alias}")

        recp = self.org.findExact("alias", self.recp)
        if len(recp) == 0:
            raise ValueError(f"no contact found with alias {self.recp!r}")
        if len(recp) > 1:
            raise ValueError(f"multiple contacts match alias {self.recp!r}, use prefix instead")

        recp = recp[0]['id']

        payload = dict(i=hab.pre, words=self.words)
        exn, _ = exchange(route="/challenge/response", payload=payload, sender=hab.pre)
        ims = hab.endorse(serder=exn, last=False, pipelined=False)
        del ims[:exn.size]

        senderHab = hab.mhab if isinstance(hab, GroupHab) else hab
        self.postman.send(src=senderHab.pre, dest=recp, topic="challenge", serder=exn, attachment=ims)
        while not self.postman.cues:
            yield self.tock

        toRemove = [self.hbyDoer, self.postman]
        self.remove(toRemove)

        return
