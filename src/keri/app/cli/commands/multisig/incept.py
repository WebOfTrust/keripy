# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.multisig module

"""

import argparse
import json
from json import JSONDecodeError

import sys
from hio.base import doing

from keri import help, kering
from keri.app import indirecting, grouping, habbing
from keri.app.cli.common import existing, displaying
from keri.core import coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a group identifier prefix')
parser.set_defaults(handler=lambda args: inceptMultisig(args))
parser.add_argument('--name', '-n', help='Human readable environment reference for local identifier', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the local identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--wait", "-w", help="number of seconds to wait for other multisig events, defaults to 10",
                    default=10)

parser.add_argument('--group', '-g', help="Human readable environment reference for group identifier", required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)


def inceptMultisig(args):
    """
    Reads the config file into a MultiSigInceptOptions dataclass and creates and signs the inception
    event for the group identifier.  If signatures are provided in the options file, the event is submitted
    to its witnesses and receipts are collected.

    Parameters:
        args: Parsed arguments from the command line

    """

    # help.ogler.level = logging.INFO
    # help.ogler.reopen(name=args.name, temp=True, clear=True)

    try:
        f = open(args.file)
        opts = json.load(f)
    except FileNotFoundError:
        print("config file", args.file, "not found")
        sys.exit(-1)
    except JSONDecodeError:
        print("config file", args.file, "not valid JSON")
        sys.exit(-1)

    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran
    group = args.group

    icpDoer = GroupMultisigIncept(name=name, base=base, alias=alias, bran=bran, group=group, wait=args.wait, **opts)

    doers = [icpDoer]
    return doers


class GroupMultisigIncept(doing.DoDoer):

    def __init__(self, name, base, alias, bran, group, wait, **kwa):
        self.name = name
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer

        self.alias = alias
        self.inits = kwa
        self.group = group
        self.wait = wait

        topics = ['/receipt', '/multisig', '/replay']
        if "delpre" in self.inits:
            topics.append('/delegate')

        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=topics)
        self.counselor = grouping.Counselor(hby=self.hby)

        doers = [self.hbyDoer, self.mbx, self.counselor]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.inceptDo)])

        super(GroupMultisigIncept, self).__init__(doers=doers)

    def inceptDo(self, tymth, tock=0.0):
        """ Create or participate in an inception event for a distributed multisig identifier

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)
        if hab is None:
            raise kering.ConfigurationError(f"invalid alias {self.alias} specified for database {self.name}")

        ghab = self.hby.habByName(name=self.group)
        if ghab is None:
            aids = self.inits["aids"]

            ghab = self.hby.makeGroupHab(group=self.group, phab=hab, **self.inits)

            print(f"Group identifier inception initialized for {ghab.pre}")
            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Seqner(sn=0)
            saider = coring.Saider(qb64=prefixer.qb64)
            self.counselor.start(aids=aids, pid=hab.pre, prefixer=prefixer, seqner=seqner, saider=saider)

        else:
            prefixer = coring.Prefixer(ghab.pre)
            seqner = coring.Seqner(sn=0)

        while True:
            saider = self.hby.db.cgms.get(keys=(prefixer.qb64, seqner.qb64))
            if saider is not None:
                break

            yield self.tock

        print()
        displaying.printIdentifier(self.hby, ghab.pre)

        self.remove(self.toRemove)

