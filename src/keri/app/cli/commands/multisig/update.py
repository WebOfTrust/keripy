# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import time

from hio import help
from hio.base import doing

from keri import kering
from keri.app import agenting, indirecting, habbing
from keri.app.cli.common import displaying
from keri.app.cli.common import existing
from keri.app.habbing import GroupHab

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Request KEL for local multisig AID from witness')
parser.set_defaults(handler=lambda args: update(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--witness', '-w', help='QB64 identifier of witness to query', default="", required=True)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)

parser.add_argument('--sn', help="Serial number of the event expected on witness", default=0, required=True)
parser.add_argument('--said', help="Said of the event expected on witness", default=None, required=True)


def update(args):
    name = args.name

    qryDoer = UpdateDoer(name=name, alias=args.alias, base=args.base, bran=args.bran, wit=args.witness, sn=args.sn,
                         said=args.said)
    return [qryDoer]


class UpdateDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, wit, sn, said, **kwa):
        doers = []
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        hab = self.hby.habByName(alias)

        if not isinstance(hab, GroupHab):
            raise kering.ConfigurationError("only group habs can be updated from witnesses.")

        self.hab = hab

        self.wit = wit
        self.sn = sn
        self.said = said
        self.cues = help.decking.Deck()

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=["/replay", "/receipt", "/reply"])
        self.witq = agenting.WitnessInquisitor(hby=self.hby)
        doers.extend([self.hbyDoer, self.mbd, self.witq])

        self.toRemove = list(doers)
        doers.extend([doing.doify(self.updateDo)])
        super(UpdateDoer, self).__init__(doers=doers, **kwa)

    def updateDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        keys = (self.hab.pre, self.wit)

        # Check for Key State from this Witness and remove if exists
        print(f"Querying witness {self.wit}")
        saider = self.hab.db.knas.get(keys)
        if saider is not None:
            self.hab.db.knas.rem(keys)
            self.hab.db.ksns.rem((saider.qb64,))
            self.hab.db.ksns.rem((saider.qb64,))

        witer = agenting.messenger(self.hab, self.wit)
        self.extend([witer])

        msg = self.hab.query(pre=self.hab.pre, src=self.wit, route="ksn")
        witer.msgs.append(bytearray(msg))

        while not witer.idle:
            yield self.tock

        self.remove([witer])

        start = time.perf_counter()
        while True:
            if (saider := self.hab.db.knas.get(keys)) is not None:
                break

            end = time.perf_counter()
            if end - start > 10:
                print("No response received from witness, exiting.")
                self.remove(self.toRemove)

                return

            yield self.tock

        print("")

        witstate = self.hab.db.ksns.get((saider.qb64,))
        if witstate.sn != self.sn and witstate.ked['d'] != self.said:
            print(f"Witness state ({witstate.sn}, {witstate.ked['d']}) does not match requested state.")
            self.remove(self.toRemove)

            return

        print("Witness at requested state, updating now...")
        self.witq.query(src=self.hab.pre, pre=self.hab.pre, r="logs")

        while True:
            yield self.tock
            kever = self.hab.kever
            if kever.serder.said == self.said:
                break

        print("")
        displaying.printIdentifier(self.hby, self.hab.pre)

        self.remove(self.toRemove)

        return
