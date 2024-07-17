# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import random
import sys
import time

from hio import help
from hio.base import doing
from keri.app import agenting, indirecting, habbing, forwarding
from keri.app.cli.common import existing, terming
from keri.app.habbing import GroupHab
from keri.app.watching import States, diffState

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Perform a one time watch of all current local AIDs')
parser.set_defaults(handler=lambda args: watch(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)


def watch(args):
    name = args.name

    qryDoer = WatchDoer(name=name, base=args.base, bran=args.bran)
    return [qryDoer]


class WatchDoer(doing.DoDoer):

    def __init__(self, name, base, bran, **kwa):
        doers = []
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.cues = help.decking.Deck()

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=["/replay", "/receipt", "/reply"])
        self.postman = forwarding.Poster(hby=self.hby)
        doers.extend([self.hbyDoer, self.mbd, self.postman, doing.doify(self.cueDo)])

        self.toRemove = list(doers)
        doers.extend([doing.doify(self.watchDo)])
        super(WatchDoer, self).__init__(doers=doers, **kwa)

    def watchDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        for hab in self.hby.habs.values():
            print(f"Processing {hab.name} ({hab.pre})")
            if len(hab.kever.wits) == 0:
                print("\tNo witnesses, skipping.")
                continue

            states = []
            for wit in hab.kever.wits:
                sys.stdout.write(f"Checking witness {wit}...")
                sys.stdout.flush()
                keys = (hab.pre, wit)

                # Check for Key State from this Witness and remove if exists
                saider = hab.db.knas.get(keys)
                if saider is not None:
                    hab.db.knas.rem(keys)
                    hab.db.ksns.rem((saider.qb64,))
                    hab.db.ksns.rem((saider.qb64,))

                witer = agenting.messenger(hab, wit)
                self.extend([witer])

                msg = hab.query(pre=hab.pre, src=wit, route="ksn")
                witer.msgs.append(bytearray(msg))

                start = time.perf_counter()
                while not witer.idle:
                    end = time.perf_counter()
                    if end - start > 10:
                        break

                    yield self.tock

                self.remove([witer])

                start = time.perf_counter()
                skip = False
                while True:
                    if (saider := hab.db.knas.get(keys)) is not None:
                        break

                    end = time.perf_counter()
                    if end - start > 10:
                        sys.stdout.write(f"{terming.Colors.FAIL} no response received{terming.Colors.ENDC}")
                        sys.stdout.flush()
                        skip = True
                        break

                    yield self.tock

                print("")

                if skip:
                    continue

                mystate = hab.kever.state()
                witstate = hab.db.ksns.get((saider.qb64,))

                states.append(diffState(wit, mystate, witstate))

            # First check for any duplicity, if so get out of here
            dups = [state for state in states if state.state == States.duplicitous]
            ahds = [state for state in states if state.state == States.ahead]
            bhds = [state for state in states if state.state == States.behind]
            if len(dups) > 0:
                print("The following witnesses have a duplicitous event:")
                for state in dups:
                    print(f"\tWitness {state.wit} at Seq No. {state.sn} with digest: {state.dig}")
                print("Further action must be taken to recover from the duplicity")

            elif len(ahds) > 0:
                # Only group habs can be behind their witnesses
                if not isinstance(hab, GroupHab):
                    print("ERROR: Single sig AID behind witnesses, aborting for this AID")
                    continue

                # First check for duplicity among the witnesses that are ahead (possible only if toad is below
                # super majority)
                digs = set([state.dig for state in ahds])
                if len(digs) > 1:  # Duplicity across witness sets
                    print(f"There are multiple duplicitous events on witnesses for {hab.pre}")
                    print("We recommend you abandon this AID")
                else:  # all witnesses that are ahead agree on the event
                    print("The following witnesses have an event that is ahead of the local KEL:")
                    for state in ahds:
                        print(f"\tWitness {state.wit} at Seq No. {state.sn} with digest: {state.dig}")

                state = random.choice(ahds)
                print("If and only if you were expecting to locally be behind your witnesses (multisig for example)")
                print("the following command can be used to locally catch up with your witness:")
                print(f"\n\tkli multisig update --name {self.hby.name} --alias {hab.name} --wit {state.wit} --sn "
                      f"{state.sn} --said {state.dig}\n")

                if len(bhds) > 0:
                    print("You have some witnesses that are also behind you, catch them up afterwards with:")
                    print(f"\n\tkli submit --name {self.hby.name} --alias {hab.name}\n")

            elif len(bhds) > 0:
                print("The following witnesses are behind the local KEL:")
                for state in bhds:
                    print(f"\tWitness {state.wit} at Seq No. {state.sn} with digest: {state.dig}")

                print("Recommend the following command to catch up witnesses:")
                print(f"\n\tkli submit --name {self.hby.name} --alias {hab.name}\n")

            else:
                print(f"Local key state is consistent with the {len(states)} (out of "
                      f"{len(hab.kever.wits)} total) witnesses that responded")

            print()

        self.remove(self.toRemove)

        return

    def cueDo(self, tymth, tock=0.0, **opts):
        """

        Handle cues coming out of our external Mailbox listener and forward to controller
        mailbox if appropriate

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.mbd.kvy.cues:
                cue = self.mbd.kvy.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue
                if cueKin == "keyStateSaved":
                    pass
                    # print("KSN Saved")

                yield self.tock
            yield self.tock
