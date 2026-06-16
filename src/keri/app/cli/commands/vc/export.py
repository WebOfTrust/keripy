# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import sys

from keri import help
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
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--said", "-s", help="SAID of the credential to export.", required=False, default=None)
parser.add_argument("--tels", help="export the transaction event logs for the credential and any chained credentials",
                    action="store_true")
parser.add_argument("--kels", help="export the key event logs for the issuer's of the credentials", action="store_true")
parser.add_argument("--chains", help="export any chained credentials", action="store_true")
parser.add_argument("--full", help="export credential, signatures, tels, kels and full chains", action="store_true")
parser.add_argument("--files", help="export artifacts to individual files keyed off of AIDs or SAIDS, default is "
                                    "stdout", action="store_true")
# Supports full state sync for late-joining multisig members
parser.add_argument("--all-registries", action="store_true",
                    help="Export all registries the controller has for the --alias (the group or AID), "
                         "along with their full registry TEL events (VCP + anc history). Combine with --kels "
                         "to also pull anchoring KEL events.")
parser.add_argument("--all-credentials", action="store_true",
                    help="Export all credentials (ACDCs + ACDC TELs (ISS/REV) + anchors) the controller has "
                         "for the --alias. Combine with --tels/--kels/--full as usual.")
parser.add_argument("--include-revoked", action="store_true",
                    help="When using --all-credentials (or the default all-creds walk), include revoked ACDCs "
                         "and their REV TEL events. Default (flag absent): only un-revoked/current credentials. "
                         "The default is the safe choice for bringing a new multisig member up to date.")


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
                    files=args.files,
                    allRegs=args.all_registries,
                    allCreds=args.all_credentials,
                    inclRev=args.include_revoked)
    return [ed]


class ExportDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, said, tels, kels, chains, files,
                 allRegs=False, allCreds=False, inclRev=False):
        self.said = said
        self.tels = tels
        self.kels = kels
        self.chains = chains
        self.files = files
        self.allRegs = allRegs
        self.allCreds = allCreds
        self.inclRev = inclRev

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)

        doers = [doing.doify(self.exportDo)]

        super(ExportDoer, self).__init__(doers=doers)

    def exit(self, deeds=None):
        """Close command-owned resources when HIO exits this doer."""
        super(ExportDoer, self).exit(deeds=deeds)
        self.close()

    def close(self):
        """Release command-owned Habery and Regery resources without clearing stores."""
        if self.rgy is not None:
            self.rgy.close()
            self.rgy = None

        if self.hby is not None:
            self.hby.close(clear=self.hby.temp)
            self.hby = None

        self.hab = None

    def exportDo(self, tymth, tock=0.0, **kwa):
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

        # walk registries for this hab, emit TELs (+ anchors via kels).
        if self.allRegs:
            self.outputAllRegistriesForHab()

        # walk credentials, respecting --include-revoked).
        doAllCreds = self.allCreds or (self.said is None and not self.allRegs)
        if doAllCreds:
            for (said,), _ in self.rgy.reger.creds.getItemIter():
                if not self.inclRev and self._isRevoked(said):
                    continue
                self.outputCred(said=said)
        elif self.said is not None:
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
            with open(f"{creder.said}-acdc.cesr", 'wb') as f:
                f.write(signing.serialize(creder, prefixer, seqner, saider))
        else:
            sys.stdout.write(signing.serialize(creder, prefixer, seqner, saider).decode("utf-8"))
            sys.stdout.flush()

    def outputAllRegistriesForHab(self):
        """Export all registries + full TELs accessible in target hab by walking Regery's
        registry records, emitting TEL history, and anchoring KEL events if --kels or --full
        """
        if self.hab is None:
            return
        pre = self.hab.pre
        # Walk regs Komer (name -> RegistryRecord with registryKey and prefix).
        for (name,), regrec in self.rgy.reger.regs.getItemIter():
            if regrec.prefix != pre:
                continue
            regk = regrec.registryKey
            self.outputTEL(regk)
            # If --kels, also emit gid's KEL to get IXNs for the VCP, ISS/REV, etc.
            if self.kels:
                self.outputKEL(pre)

    def _isRevoked(self, said):
        """Return True if the credential identified by said has a revocation event in its TEL."""
        try:
            for msg in self.rgy.reger.clonePreIter(pre=said):
                serder = serdering.SerderKERI(raw=msg)
                ilk = serder.ked.get("t")
                if ilk in ("rev", "brv"):
                    return True
        except Exception:
            # If we cannot walk the TEL for any reason, be conservative and do not filter it out.
            return False
        return False

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
