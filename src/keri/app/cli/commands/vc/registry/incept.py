import argparse

from hio import help
from hio.base import doing

from keri.app import directing, indirecting
from keri.app.cli.common import existing
from keri.vdr import registering

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: registryIncept(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None)
parser.add_argument("--no-backers", "-nb", help="do not allow setting up backers different from the ahcnoring KEL "
                                                "witnesses", default=True, action="store")
parser.add_argument('--backers', '-b', help='New set of backers different from the anchoring KEL witnesses.  Can '
                                            'appear multiple times', metavar="<prefix>", default=[], action="append",
                    required=False)
parser.add_argument("--establishment-only", "-e", help="Only allow establishment events for the anchoring events of "
                                                       "this registry", default=False, action="store")


def registryIncept(args):
    name = args.name
    registryName = args.registry_name if args.registry_name is not None else name
    estOnly = args.establishment_only
    noBackers = args.no_backers
    backers = args.backers

    if noBackers and backers:
        print("--no-backers and --backers can not both be provided")
        return -1

    icpDoer = RegistryInceptor(name=name, registryName=registryName, estOnly=estOnly, noBackers=noBackers, baks=backers)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class RegistryInceptor(doing.DoDoer):
    """

    """
    def __init__(self, name, registryName, **kwa):
        """


        """
        self.name = name
        self.registryName = registryName
        self.hab, doers = existing.openHabitat(name=self.name)
        mbx = indirecting.MailboxDirector(hab=self.hab, topics=["/receipt"])
        self.icpr = registering.RegistryInceptDoer(hab=self.hab)
        doers.extend([self.icpr, mbx])
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.inceptDo)])
        super(RegistryInceptor, self).__init__(doers=doers, **kwa)


    def inceptDo(self, tymth, tock=0.0, **kwa):
        """


        """
        yield self.tock

        msg = dict(name=self.registryName)
        self.icpr.msgs.append(msg)

        while not self.icpr.cues:
            yield self.tock

        rep = self.icpr.cues.popleft()
        regk = rep["regk"]
        print("Regsitry:  {}({}) \n\tcreated for Identifier Prefix:  {}".format(self.registryName, regk, self.hab.pre))

        self.remove(self.toRemove)
