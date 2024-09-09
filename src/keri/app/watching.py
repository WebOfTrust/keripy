# -*- encoding: utf-8 -*-
"""
KERI
keri.app.watching module

"""
import random
from collections import namedtuple
from dataclasses import dataclass

from hio.base import doing
from hio.help import decking

from keri import help

logger = help.ogler.getLogger()

Stateage = namedtuple("Stateage", 'even ahead behind duplicitous')

States = Stateage(even="even", ahead="ahead", behind="behind", duplicitous="duplicitous")


@dataclass
class DiffState:
    """ Difference between a remote KeyStateRecord and local for the same AID.

    Uses Stateage to represent whether the remote KSR is even, ahead, behind or duplicitous

    """
    pre: str  # The AID of the KSR
    wit: str  # The entity reporting the KSR (non-local)
    state: Stateage  # The state of the remote KSR relative to local
    sn: int  # The sequence number of the remote KSR
    dig: str  # The digest of the latest event of the remote KSR


class Adjudicator:
    """ The Adjudicator of Key State

    This class performs key state adjudication by checking any key state reported by the watcher set for a given
    watched AID and compares the reported values against the local key state for the watched AID and the key state
    of all other responding watchers.  It uses a per-adjudication threshold to determine what is acceptable duplicity
    for each adjudication.

    Cues are sent out for each round of adjudication with the following kins:

       keyStateConsistent - Key state of all queries watchers is consistent with local key state
       keyStateLagging - Key state from some watchers is behind local key state and other watchers
       keyStateUpdate - A threshold satisfying number of watchers report new key state for watched AID
       keyStateDuplicitous - Duplicity has been detected on some set of watchers (provided in the cue)

    Consumers of the Adjudicator's cues are safe to retrieve new key state from one of the Watchers listed in the
    cue of `keyStateUpdated` is received.  All other kins require controller intervention and should be bubbled up.

    """

    def __init__(self, hby, hab, msgs=None, cues=None):
        """ Create instance of Adjudicator for adjudicating key state

        Parameters:
            hby (Habery): database and Habitat environment
            hab (Hab): identifier database environment
            msgs (Deck): incoming requests to adjudicate key state
            cues (Deck): outgoing responses to adjudication of key state

        """
        self.hby = hby
        self.hab = hab
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

    def performAdjudications(self):
        """ Process loop of existing messages requesting key state adjudication """
        while self.msgs:
            msg = self.msgs.pull()

            watched = msg["oid"]
            toad = msg["toad"] if "toad" in msg else None

            self.adjudicate(watched, toad)

    def adjudicate(self, watched, toad=None):
        """ Perform key state adjudication against the `watched` AID and provided threshold

        If `toad` is not provided, the full set of watchers must come to consensus before `keyStateUpdate`
        will be reported.

        Parameters:
            watched (str): qb64 AID to adjudicate for key state duplicity
            toad (int): threshold of acceptable duplicity amongst available watchers


        """
        watchers = set()
        for (cid, aid, oid), observed in self.hab.db.obvs.getItemIter(keys=(self.hab.pre,)):
            if observed.enabled and oid == watched:
                watchers.add(aid)

        toad = int(toad) if toad else len(watchers)
        if toad > len(watchers):
            raise ValueError(f"Threshold of {toad} is greater than number watchers {len(watchers)}")

        states = []
        mystate = self.hab.kevers[watched].state()
        for watcher in watchers:
            saider = self.hab.db.knas.get(keys=(watched, watcher))
            if saider is None:
                logger.info(f"No key state from watcher {watcher} for {watched}")
                continue

            ksn = self.hab.db.ksns.get(keys=(saider.qb64,))
            states.append(diffState(watcher, mystate, ksn))

        dups = [state for state in states if state.state == States.duplicitous]
        ahds = [state for state in states if state.state == States.ahead]
        bhds = [state for state in states if state.state == States.behind]

        if len(dups) > 0:
            cue = dict(kin="keyStateDuplicitous", cid=self.hab.pre, oid=watched, wids=watchers, dups=dups)
            self.cues.append(cue)

            logger.error(f"Duplicity detected for AID {watched}, local key state remains intact.")
            for state in dups:
                logger.error(f"\tWatcher {state.wit} at seq No. {state.sn} with digest: {state.dig}")

        elif len(ahds) > 0:
            # Only group habs can be behind their watchers
            # First check for duplicity among the watchers that are ahead (possible only if toad is below
            # super majority)
            digs = set([state.dig for state in ahds])
            if len(digs) > 1:  # Duplicity across watcher sets
                cue = dict(kin="keyStateDuplicitous", cid=self.hab.pre, oid=watched, wids=watchers, dups=ahds)
                self.cues.append(cue)

                logger.error(f"There are multiple duplicitous events on watcher for {watched}")
                for state in ahds:
                    logger.error(f"\tWatcher {state.wit} at seq No. {state.sn} with digest: {state.dig}")

            elif len(ahds) >= toad:  # all witnesses that are ahead agree on the event
                logger.info(f"Threshold ({toad}) satisfying number of watchers ({len(ahds)}) are ahead")
                for state in ahds:
                    logger.info(f"\tWatcher {state.wit} at Seq No. {state.sn} with digest: {state.dig}")

                state = random.choice(ahds)
                cue = dict(kin="keyStateUpdate", cid=self.hab.pre, oid=watched, wids=watchers, sn=state.sn, aheads=ahds)
                self.cues.append(cue)

        elif len(bhds) > 0:
            cue = dict(kin="keyStateLagging", cid=self.hab.pre, oid=watched, wids=watchers, behind=bhds)
            self.cues.append(cue)

            logger.info("The following watchers are behind the local KEL:")
            for state in bhds:
                logger.info(f"\tWatcher {state.wit} at seq No. {state.sn} with digest: {state.dig}")

            logger.info(f"Recommend the checking those watchers for access to {watched} witnesses")

        else:
            cue = dict(kin="keyStateConsistent", cid=self.hab.pre, oid=watched, wids=watchers, states=states)
            self.cues.append(cue)
            logger.info(f"Local key state is consistent with the {len(states)} (out of "
                        f"{len(watchers)} total) watchers that responded")


class AdjudicationDoer(doing.Doer):
    """ Doer class responsible for process adjudication requests in an Adjudicator's msgs """

    def __init__(self, adjudicator):
        """ Create instance of Doer for performing key state adjudications """
        self.adjudicator = adjudicator
        super(AdjudicationDoer, self).__init__()

    def recur(self, tyme):
        """ Perform one pass over all adjudication requests

        Parameters:
            tyme (float): relative cycle time

        Returns:

        """
        self.adjudicator.performAdjudications()


def diffState(wit, preksn, witksn):
    """ Return a record of the differences between the states provided by `wit` and local state

    Parameters:
        wit (str): qb64 AID of entity reporting key state
        preksn (KeyStateRecord): Local key state of AID
        witksn (KeyStateRecord): Key state of AID as provided by `wit`

    Returns:
        state (WitnessState): record indicating the differenced between the two provided KSN records

    """
    mypre = preksn.i
    pre = witksn.i
    mysn = int(preksn.s, 16)
    mydig = preksn.d
    sn = int(witksn.s, 16)
    dig = witksn.d

    if pre != mypre:
        raise ValueError(f"can't compare key states from different AIDs {mypre}/{pre}")

    # At the same sequence number, check the DIGs
    if mysn == sn:
        if mydig == dig:
            state = States.even
        else:
            state = States.duplicitous

    # This witness is behind and will need to be caught up.
    elif mysn > sn:
        state = States.behind

    # mysn < witstate.sn - We are behind this witness (multisig or restore situation).
    # Must ensure that controller approves this event or a recovery rotation is needed
    else:
        state = States.ahead

    return DiffState(pre, wit, state, sn, dig)
