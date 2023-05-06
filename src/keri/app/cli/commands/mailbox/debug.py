# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri import kering
from keri.app import agenting, indirecting, habbing, httping
from keri.app.cli.common import displaying, existing
from keri.app.habbing import GroupHab
from keri.core import coring
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Display mailbox status for an identifier and witness')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--witness', '-w', help='The qualified b64 AID of the witness to poll', required=True)
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def handler(args):
    """
    Submit KERI identifier prefix to its witnesses for receipts.

    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    witness = args.witness
    verbose = args.verbose

    icpDoer = ReadDoer(name=name, base=base, alias=alias, bran=bran, witness=witness, verbose=verbose)

    doers = [icpDoer]
    return doers


class ReadDoer(doing.DoDoer):
    """ DoDoer for creating a new identifier prefix and Hab with an alias.
    """

    def __init__(self, name, base, alias, bran, witness, verbose):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.alias = alias
        self.hby = hby
        self.witness = witness
        self.verbose = verbose

        doers = [self.hbyDoer, doing.doify(self.readDo)]

        super(ReadDoer, self).__init__(doers=doers)

    def readDo(self, tymth, tock=0.0):
        """
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

        hab = self.hby.habByName(name=self.alias)
        topics = {"/receipt": 0, "/replay": 0, "/multisig": 0, "/credential": 0, "/delegate": 0, "/challenge": 0,
                  "/oobi": 0}
        try:
            client, clientDoer = agenting.httpClient(hab, self.witness)
        except kering.MissingEntryError as e:
            raise ValueError(f"error connecting to witness {self.witness}: {e}")

        self.extend([clientDoer])

        print("Local Index per Topic")
        witrec = hab.db.tops.get((hab.pre, self.witness))
        for topic in witrec.topics:
            print(f"   Topic {topic}:   {witrec.topics[topic]}")
        print()

        q = dict(pre=hab.pre, topics=topics)
        if isinstance(hab, GroupHab):
            msg = hab.mhab.query(pre=hab.pre, src=self.witness, route="mbx", query=q)
        else:
            msg = hab.query(pre=hab.pre, src=self.witness, route="mbx", query=q)

        httping.createCESRRequest(msg, client, dest=self.witness)

        while client.requests:
            yield self.tock

        yield 1.0
        print("Messages:")
        while client.events:
            evt = client.events.popleft()
            if "id" not in evt or "data" not in evt or "name" not in evt:
                print(f"bad mailbox event: {evt}")
                continue
            idx = evt["id"]
            msg = evt["data"]
            tpc = evt["name"]

            if not self.verbose:
                print(f"Topic {tpc}: {idx}: {msg[0:20]}")
            else:
                print(f"  Topic: {tpc}")
                print(f"  Index: {idx}")
                print(f"  {msg}")
                print()

        self.remove([self.hbyDoer, clientDoer])
        return
