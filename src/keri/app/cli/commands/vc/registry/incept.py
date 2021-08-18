import argparse

from hio import help
from hio.base import doing
from keri.app import directing, agenting
from keri.app.cli.common import existing
from keri.vdr import issuing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: registryIncept(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument("--no-backers", "-nb", help="do not allow setting up backers different from the ahcnoring KEL "
                                                "witnesses", default=True, action="store")
parser.add_argument('--backers', '-b', help='New set of backers different from the anchoring KEL witnesses.  Can '
                                            'appear multiple times', metavar="<prefix>", default=[], action="append",
                    required=False)
parser.add_argument("--establishment-only", "-e", help="Only allow establishment events for the anchoring events of "
                                                       "this registry", default=False, action="store")


def registryIncept(args):
    name = args.name
    estOnly = args.establishment_only
    noBackers = args.no_backers
    backers = args.backers

    if noBackers and backers:
        print("--no-backers and --backers can not both be provided")
        return -1

    icpDoer = RegistryInceptDoer(name=name, estOnly=estOnly, noBackers=noBackers, baks=backers)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class RegistryInceptDoer(doing.DoDoer):

    def __init__(self, name, **kwa):

        self.name = name
        hab, doers = existing.openHabitat(name=self.name)
        self.hab = hab
        self.toRemove = list(doers)  # make copy so we don't try to remove our own dofied method

        doers.extend([doing.doify(self.inceptDo, **kwa)])
        super(RegistryInceptDoer, self).__init__(doers=doers)


    def inceptDo(self, tymth, tock=0.0, **kwa):
        """
        Returns:  doifiable Doist compatible generator method for creating a registry
        and sending its inception and anchoring events to witnesses or backers

        Usage:
            add result of doify on this method to doers list
        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        issuer = issuing.Issuer(hab=self.hab, name=self.name, **kwa)
        yield self.tock

        kevt = issuer.incept
        tevt = issuer.ianchor

        witDoer = agenting.WitnessReceiptor(hab=self.hab, msg=kevt)
        witSender = agenting.WitnessSender(hab=self.hab, msg=tevt)
        self.extend([witDoer, witSender])
        self.toRemove.extend([witDoer, witSender])
        _ = yield self.tock

        while not witDoer.done and not witSender.done:
            _ = yield self.tock


        print("Regsitry:  {} \n\tcreated for Identifier Prefix:  {}".format(issuer.regk, self.hab.pre))

        self.remove(self.toRemove)
