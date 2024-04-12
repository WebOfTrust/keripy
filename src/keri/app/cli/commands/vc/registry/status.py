import argparse

from hio import help
from hio.base import doing

from keri.app import indirecting, habbing, grouping
from keri.app.cli.common import existing
from keri.core import coring, serdering
from keri.vdr import credentialing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: registryStatus(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None, required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def registryStatus(args):
    name = args.name
    bran = args.bran
    base = args.base
    verbose = args.verbose
    registryName = args.registry_name

    icpDoer = RegistryStatusor(name=name, base=base, bran=bran, registryName=registryName, verbose=verbose)

    doers = [icpDoer]
    return doers


class RegistryStatusor(doing.DoDoer):
    """

    """

    def __init__(self, name, base, bran, registryName, verbose):
        """


        """
        self.name = name
        self.registryName = registryName
        self.verbose = verbose
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        counselor = grouping.Counselor(hby=self.hby)

        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/replay"])
        doers = [self.hbyDoer, counselor, mbx]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.statusDo)])
        super(RegistryStatusor, self).__init__(doers=doers)

    def statusDo(self, tymth, tock=0.0):
        """ Process incoming messages to incept a credential registry

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

        reg = self.rgy.registryByName(self.registryName)
        print(f"Registry:  {reg.regk}")
        print(f"Seq No.  {reg.tever.sn}")
        print(f"    Controlling Identifier:  {reg.hab.pre}")
        print()

        if reg.tever.noBackers:
            print("Backers: Not supported")
        else:
            print("\nBackers:")
            print("Count:\t\t{}".format(len(reg.tever.baks)))
            print("Threshold:\t{}".format(reg.tever.toad))

        if reg.estOnly:
            print("Events:\tEstablishment Only")
        else:
            print("Events:\tInteraction Allowed")

        print()
        if self.verbose:
            cloner = reg.reger.clonePreIter(pre=reg.regk, fn=0)  # create iterator at 0
            for msg in cloner:
                srdr = serdering.SerderKERI(raw=msg)
                print(srdr.pretty())
                print()

        self.remove(self.toRemove)

