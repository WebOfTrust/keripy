# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import datetime
import random
import sys
from dataclasses import asdict

from hio import help
from hio.base import doing

from keri.app import connecting, indirecting, querying
from keri.app.cli.common import existing
from keri.app.watching import diffState, States
from keri.help import helping
from keri.kering import ConfigurationError
logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Perform key event adjudication on any new key state from watchers.')
parser.set_defaults(handler=lambda args: handle(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--toad', '-t', default=None, required=False, type=int,
                    help='int of watcher threshold (threshold of acceptable duplicity)', )
parser.add_argument("--watched", '-W', help="the watched AID or alias to add", required=True)
parser.add_argument("--poll", "-P", help="Poll mailboxes for any issued credentials", action="store_true")


def handle(args):
    """ Command line handler for adding an aid to a watcher's list of AIds to watch

    Parameters:
        args(Namespace): parsed command line arguments

    """

    kwa = dict(args=args)
    adjudicator = AdjudicationDoer(**kwa)

    return [adjudicator]


class AdjudicationDoer(doing.DoDoer):

    def __init__(self, **kwa):
        args = kwa["args"]
        base = args.base
        bran = args.bran
        self.name = args.name
        self.alias = args.alias
        self.watched = args.watched
        self.poll = args.poll
        self.toad = args.toad

        self.hby = existing.setupHby(name=self.name, base=base, bran=bran)
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/reply', '/replay'])
        doers = [doing.doify(self.adjudicate, **kwa), self.mbx]

        super(AdjudicationDoer, self).__init__(**kwa, doers=doers)

    def adjudicate(self, tymth, tock=0.0, **opts):
        """ Command line status handler

        """
        _ = (yield tock)

        try:
            org = connecting.Organizer(hby=self.hby)

            if self.poll:
                end = helping.nowUTC() + datetime.timedelta(seconds=5)
                sys.stdout.write(f"Polling mailboxes")
                sys.stdout.flush()
                while helping.nowUTC() < end:
                    sys.stdout.write(".")
                    sys.stdout.flush()
                    yield 1.0
                print("\n")

            if self.watched in self.hby.kevers:
                watd = self.watched
            else:
                watd = org.find("alias", self.watched)
                if len(watd) != 1:
                    raise ValueError(f"invalid recipient {self.watched}")
                watd = watd[0]['id']

            if not watd:
                raise ValueError(f"unknown watched {self.watched}")

            if self.alias is None:
                self.alias = existing.aliasInput(self.hby)

            hab = self.hby.habByName(self.alias)
            if hab is None:
                raise ValueError(f"unknown alias {self.alias}")

            watchers = set()
            for (cid, aid, oid), observed in hab.db.obvs.getItemIter(keys=(hab.pre,)):
                if observed.enabled:
                    watchers.add(aid)

            toad = int(self.toad) if self.toad else len(watchers)
            if toad > len(watchers):
                raise ValueError(f"Threshold of {toad} is greater than number watchers {len(watchers)}")

            states = []
            mystate = hab.kever.state()
            for watcher in watchers:
                saider = hab.db.knas.get(keys=(self.watched, watcher))
                if saider is None:
                    print(f"No key state from watcher {watcher} for {self.watched}")
                    continue

                ksn = hab.db.ksns.get(keys=(saider.qb64,))
                states.append(diffState(watcher, mystate, ksn))

            dups = [state for state in states if state.state == States.duplicitous]
            ahds = [state for state in states if state.state == States.ahead]
            bhds = [state for state in states if state.state == States.behind]

            if len(dups) > 0:
                logger.error(f"Duplicity detected for AID {self.watched}, local key state remains intact.")
                for state in dups:
                    logger.error(f"\tWatcher {state.wit} at seq No. {state.sn} with digest: {state.dig}")

            elif len(ahds) > 0:
                # Only group habs can be behind their witnesses
                # First check for duplicity among the witnesses that are ahead (possible only if toad is below
                # super majority)
                digs = set([state.dig for state in ahds])
                if len(digs) > 1:  # Duplicity across witness sets
                    logger.error(f"There are multiple duplicitous events on watcher for {self.watched}")
                    for state in ahds:
                        logger.error(f"\tWatcher {state.wit} at seq No. {state.sn} with digest: {state.dig}")
                elif len(ahds) >= self.toad:  # all witnesses that are ahead agree on the event
                    logger.info(f"Threshold ({self.toad}) satisfying number of watchers ({len(ahds)}) are ahead")
                    for state in ahds:
                        logger.info(f"\tWatcher {state.wit} at Seq No. {state.sn} with digest: {state.dig}")

                state = random.choice(ahds)
                querier = querying.SeqNoQuerier(hby=self.hby, hab=hab, pre=self.watched, sn=state.sn, wits=[state.wit])
                self.extend([querier])

                while not querier.done:
                    yield self.tock

            elif len(bhds) > 0:
                logger.info("The following watchers are behind the local KEL:")
                for state in bhds:
                    logger.info(f"\tWatcher {state.wit} at seq No. {state.sn} with digest: {state.dig}")

                logger.info(f"Recommend the checking those watchers for access to {self.watched} witnesses")

            else:
                logger.info(f"Local key state is consistent with the {len(states)} (out of "
                            f"{len(hab.kever.wits)} total) watchers that responded")

        except ConfigurationError as e:
            print(f"identifier prefix for {self.name} does not exist, incept must be run first", )
            return -1

        self.remove([self.mbx])
