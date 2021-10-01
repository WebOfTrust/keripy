# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.multisig module

"""

import argparse
import json
import logging
import sys
from json import JSONDecodeError

from hio.base import doing
from hio.help import decking

from keri import help
from keri.app import directing, indirecting, grouping, agenting
from keri.app.cli.common import displaying, existing

# help.ogler.level = logging.INFO
# help.ogler.reopen(name="hio", temp=True, clear=True)

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a group identifier prefix')
parser.set_defaults(handler=lambda args: inceptMultisig(args))
parser.add_argument('--name', '-n', help='Human readable environment reference for local identifier', required=True)
parser.add_argument('--group', '-g', help="Human readable environment reference for group identifier", required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--proto', '-p', help='Protocol to use when propagating ICP to witnesses [tcp|http] (defaults '
                                          'http)', default="http")


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
    group = args.group

    icpDoer = GroupMultisigIncept(name=name, group=group, proto=args.proto, **opts)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class GroupMultisigIncept(doing.DoDoer):

    def __init__(self, name, group, **kwa):
        self.name = name
        self.hab, doers = existing.openHabitat(name=name)
        self.msg = kwa
        self.msg["group"] = group

        topics = ['/receipt', '/multisig', '/replay']
        if "delpre" in self.msg:
            topics.append('/delegate')


        self.mbd = indirecting.MailboxDirector(hab=self.hab, topics=topics)
        self.icpr = grouping.MultiSigGroupDoer(hab=self.hab, ims=self.mbd.ims)
        self.witq = agenting.WitnessInquisitor(hab=self.hab, klas=agenting.HttpWitnesser)


        doers.extend([self.witq, doing.doify(self.cueDo), self.icpr, self.mbd])
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.inceptDo)])

        super(GroupMultisigIncept, self).__init__(doers=doers)

    def inceptDo(self, tymth, tock=0.0, **opts):
        # enter context
        yield self.tock

        self.msg["op"] = grouping.Ops.icp
        self.icpr.msgs.append(self.msg)

        while not self.icpr.cues:
            yield self.tock

        rep = self.icpr.cues.popleft()


        print()
        print("Group Identifier Inception Complete:")
        displaying.printIdentifier(self.hab, rep["pre"])

        self.remove(self.toRemove)

    def cueDo(self, tymth, tock=0.0, **opts):
        """

        Handle cues coming out of our external Mailbox listener and forward to controller
        mailbox if appropriate

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.mbd.cues:
                cue = self.mbd.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue
                if cueKin in ("psUnescrow",):
                    if self.icpr.msgToSend is not None:

                        witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=self.icpr.msgToSend,
                                                               klas=agenting.TCPWitnesser)
                        self.extend([witRctDoer])

                        while not witRctDoer.done:
                            _ = yield self.tock

                        self.remove([witRctDoer])

                        serder = cue["serder"]
                        self.icpr.cues.append(dict(pre=serder.pre))
                elif cue["kin"] == "delegatage":
                    delpre = cue["delpre"]
                    self.witq.query(delpre)

                yield self.tock
            yield self.tock

