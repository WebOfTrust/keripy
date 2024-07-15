# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri.core import serdering
from ..common import existing
from ... import habbing, connecting, forwarding

parser = argparse.ArgumentParser(description='Send an rpy /introduce message to recipient with OOBI')
parser.set_defaults(handler=lambda args: introduce(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--recipient', help='alias or contact to send the introduction to', required=True)
parser.add_argument('--introducee', help='alias or contact of the OOBI to send', required=True)
parser.add_argument("--role", "-r", help="role of oobi to send", required=True)


def introduce(args):
    """
    Performs a rotation of the identifier of the environment represented by the provided name parameter

        args (parseargs):  Command line argument

    """
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran
    introducee = args.introducee
    recipient = args.recipient
    role = args.role

    ixnDoer = IntroduceDoer(name=name, base=base, alias=alias, bran=bran, introducee=introducee, recipient=recipient,
                            role=role,)

    return [ixnDoer]


class IntroduceDoer(doing.DoDoer):
    """

       DoDoer that launches Doers needed to introduce one controller of an AID to another

    """

    def __init__(self, name, base, bran, alias, introducee, recipient, role):
        """
        Returns DoDoer with all registered Doers needed to perform an introduction.

        Parameters:
            name is human readable str of identifier
       """

        self.alias = alias
        self.introducee = introducee
        self.recipient = recipient
        self.role = role

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.org = connecting.Organizer(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby)
        doers = [self.hbyDoer, self.postman, doing.doify(self.introduceDo)]

        super(IntroduceDoer, self).__init__(doers=doers)

    def introduceDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)

        if self.recipient in self.hby.kevers:
            recp = self.recipient
        else:
            recp = self.org.find("alias", self.recipient)
            if len(recp) != 1:
                raise ValueError(f"invalid recipient {self.recipient}")
            recp = recp[0]['id']

        if (ihab := self.hby.habByName(self.introducee)) is not None:
            introducee = ihab.pre
        elif self.introducee in self.hby.habs:
            introducee = self.introducee
        elif self.introducee in self.hby.kevers:
            introducee = self.introducee
        else:
            introducee = None
            results = self.org.find("alias", self.introducee)
            for result in results:
                if result["alias"] == self.introducee:
                    introducee = result['id']
            if not introducee:
                raise ValueError(f"invalid introducee {self.introducee}")

        oobi = None
        for (key,), obr in self.hby.db.roobi.getItemIter():
            if obr.cid == introducee and obr.role == self.role:
                oobi = key

        if oobi is None:
            raise ValueError(f"Unable to find OOBI with role {self.role} for {introducee}")

        msg = hab.reply(route="/introduce", data=dict(
            cid=hab.pre,
            oobi=oobi
        ))

        serder = serdering.SerderKERI(raw=msg)
        atc = msg[serder.size:]
        self.postman.send(src=hab.pre, dest=recp, topic="credential", serder=serder,
                          attachment=atc)

        while not len(self.postman.cues) == 1:
            yield self.tock

        print(f"Introduction with OOBI {oobi} sent for {self.introducee} sent to {self.recipient}")

        toRemove = [self.hbyDoer, self.postman]
        self.remove(toRemove)

        return
