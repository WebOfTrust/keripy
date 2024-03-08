# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import sys

from hio import help
from hio.base import doing

from keri.app import signing
from keri.app.cli.common import existing
from keri.core import serdering
from keri.vdr import credentialing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='List credentials and check mailboxes for any newly issued credentials')
parser.set_defaults(handler=lambda args: export_credentials(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--said", "-s", help="SAID of the credential to export.", required=False, default=None)
parser.add_argument("--tels", help="export the transaction event logs for the credential and any chained credentials",
                    action="store_true")
parser.add_argument("--kels", help="export the key event logs for the issuer's of the credentials", action="store_true")
parser.add_argument("--chains", help="export any chained credentials", action="store_true")
parser.add_argument("--full", help="export credential, signatures, tels, kels and full chains", action="store_true")
parser.add_argument("--files", help="export artifacts to individual files keyed off of AIDs or SAIDS, default is "
                                    "stdout", action="store_true")


def export_credentials(args):
    """ Command line list credential registries handler

    """
    tels = args.tels
    kels = args.kels
    chains = args.chains if args.chains is not None else {}

    if args.full:
        tels = kels = chains = True

    ed = ExportDoer(name=args.name,
                    alias=args.alias,
                    base=args.base,
                    bran=args.bran,
                    said=args.said,
                    tels=tels,
                    kels=kels,
                    chains=chains,
                    files=args.files)
    return [ed]


class ExportDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, said, tels, kels, chains, files):
        self.said = said
        self.tels = tels
        self.kels = kels
        self.chains = chains
        self.files = files

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)

        doers = [doing.doify(self.exportDo)]

        super(ExportDoer, self).__init__(doers=doers)

    def exportDo(self, tymth, tock=0.0):
        """ Export credential from store and any related material

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

        if self.said is None:
            for (said,), _ in self.rgy.reger.creds.getItemIter():
                self.outputCred(said=said)

        else:
            self.outputCred(said=self.said)

    def outputCred(self, said):
        creder, *_ = self.rgy.reger.cloneCred(said=said)

        if self.kels:
            issr = creder.issuer
            self.outputKEL(issr)

        if self.tels:
            if creder.regi is not None:
                self.outputTEL(creder.regi)
                self.outputTEL(creder.said)

        if self.chains:
            chains = creder.edge if creder.edge is not None else {}
            saids = []
            for key, source in chains.items():
                if key == 'd':
                    continue

                if not isinstance(source, dict):
                    continue

                saids.append(source['n'])

            for said in saids:
                self.outputCred(said)

        (prefixer, seqner, saider) = self.rgy.reger.cancs.get(keys=(creder.said,))
        if self.files:
            f = open(f"{creder.said}-acdc.cesr", 'w')
            f.write(signing.serialize(creder, prefixer, seqner, saider))
            f.close()
        else:
            sys.stdout.write(signing.serialize(creder, prefixer, seqner, saider).decode("utf-8"))
            sys.stdout.flush()

    def outputTEL(self, regk):
        f = None
        if self.files:
            f = open(f"{regk}-tel.cesr", "w")

        for msg in self.rgy.reger.clonePreIter(pre=regk):
            if f is not None:
                f.write(msg.decode("utf-8"))
            else:
                serder = serdering.SerderKERI(raw=msg)
                atc = msg[serder.size:]
                sys.stdout.write(serder.raw.decode("utf-8"))
                sys.stdout.write(atc.decode("utf-8"))

        if f is not None:
            f.close()

    def outputKEL(self, pre):
        f = None
        if self.files:
            f = open(f"{pre}-kel.cesr", "w")

        for msg in self.hby.db.clonePreIter(pre=pre):
            if f is not None:
                f.write(msg.decode("utf-8"))
            else:
                serder = serdering.SerderKERI(raw=msg)
                atc = msg[serder.size:]
                sys.stdout.write(serder.raw.decode("utf-8"))
                sys.stdout.write(atc.decode("utf-8"))

        if f is not None:
            f.close()
