"""
tests.app.app_helpers module

Helpers for test setup including context managers for witnesses, controllers,
and orchestration Doers for multisig and delegation workflows.
"""
import json
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import List, Generator, Tuple

from hio.base import Doer, doing, Doist
from hio.help import decking

from keri import kering
from keri.app import habbing, delegating, grouping, oobiing
from keri.app.agenting import WitnessReceiptor, Receiptor, WitnessInquisitor
from keri.app.configing import Configer
from keri.app.delegating import Anchorer
from keri.app.forwarding import Poster
from keri.app.habbing import openHab, HaberyDoer, Habery, Hab, openHby, GroupHab
from keri.app.indirecting import MailboxDirector, setupWitness
from keri.app.notifying import Notifier
from keri.core import Salter, coring, serdering, indexing
from keri.db import basing, dbing
from keri.help import helping
from keri.peer import exchanging
from keri.peer.exchanging import Exchanger


# =============================================================================
# Data Classes for Structured Returns
# =============================================================================

@dataclass
class EscrowDoer(doing.Doer):
    """
    Doer that processes escrows for both Habery's Kevery and Counselor.
    This Doer is just a testing helper to speed up event processing in tests.

    This fills a gap in the standard controller setup where:
    - MailboxDirector.escrowDo processes mbx.kvy escrows (a separate Kevery for remote events)
    - Counselor.escrowDo processes counselor escrows but with yield 0.5 delay, not great for tests that should run as fast as possible.
    - Nothing processes hby.kvy escrows (the Habery's Kevery for local events)

    This doer runs both processEscrows calls on every recur for faster test execution.
    """

    def __init__(self, hby: Habery, counselor: grouping.Counselor = None, **kwa):
        super(EscrowDoer, self).__init__(**kwa)
        self.hby = hby
        self.counselor = counselor

    def recur(self, tyme):
        """Process escrows on every recur call for responsive tests."""
        self.hby.kvy.processEscrows()
        if self.counselor is not None:
            self.counselor.processEscrows()
        return False  # Keep running


@dataclass
class ControllerContext:
    """Structured context for a KERI controller with all its components."""
    hby: Habery
    doers: List[Doer]
    hbyDoer: HaberyDoer
    anchorer: Anchorer
    postman: Poster
    exc: Exchanger
    notifier: Notifier
    mbx: MailboxDirector
    witReceiptor: WitnessReceiptor
    receiptor: Receiptor
    witq: WitnessInquisitor = None
    counselor: grouping.Counselor = None


@dataclass
class WitnessContext:
    """Structured context for a KERI witness."""
    hby: Habery
    hab: Hab
    doers: List[Doer]
    oobi: str
    pre: str = field(init=False)

    def __post_init__(self):
        self.pre = self.hab.pre


# =============================================================================
# Context Managers
# =============================================================================

@contextmanager
def openWit(name: str = 'wan', tcpPort: int = 6632, httpPort: int = 6642,
            salt: bytes = b'abcdefg0123456789') -> Generator[WitnessContext, None, None]:
    """
    Context manager for a KERI witness along with the Doers needed to run it.
    Expects the Doers to be run by the caller.

    Returns a WitnessContext with (Habery, Hab, witness Doers, witness controller OOBI URL)
    """
    saltQb64 = Salter(raw=salt).qb64
    # Witness config - use temp=True to avoid filesystem permission issues in tests
    witCfg = f"""{{
          "dt": "2025-12-11T11:02:30.302010-07:00",
          "{name}": {{
            "dt": "2025-12-11T11:02:30.302010-07:00",
            "curls": ["tcp://127.0.0.1:{tcpPort}/", "http://127.0.0.1:{httpPort}/"]}}}}"""
    cf = Configer(name=name, temp=True, reopen=True, clear=False)
    cf.put(json.loads(witCfg))
    with (
            openHab(salt=bytes(saltQb64, 'utf-8'), name=name, transferable=False, temp=True, cf=cf) as (hby, hab)
    ):
        oobi = f'http://127.0.0.1:{httpPort}/oobi/{hab.pre}/controller?name={name}&tag=witness'
        hbyDoer = HaberyDoer(habery=hby)
        doers: List[Doer] = [hbyDoer]
        doers.extend(setupWitness(alias=name, hby=hby, tcpPort=tcpPort, httpPort=httpPort))
        yield WitnessContext(hby=hby, hab=hab, doers=doers, oobi=oobi)


@contextmanager
def openCtrlWited(name: str = 'aceCtlrKS',
                  salt: bytes = b'aaaaaaa0123456789') -> Generator[ControllerContext, None, None]:
    """
    Context manager for setting up a KERI controller that uses a witness as its mailbox and witness.
    Sets up the Doers needed to run a controller including both single sig and multi-sig handlers.
    Relies on an outer context manager or caller to perform OOBI resolution and inception of the controller AID.

    Expects the Doers to be run by the caller.

    Returns a ControllerContext with all components accessible.
    """
    # Note: Avoid puting iurls in config - that causes auto-resolution during init
    # which hangs if the witness isn't running yet. Resolve OOBIs manually instead
    # unless you make sure the witness context is both created and running before
    # creating this controller.
    ctlrCfg = f"""{{"dt": "2025-12-11T11:02:30.302010-07:00"}}"""
    cf = Configer(name=name, temp=True, reopen=True, clear=False)
    cf.put(json.loads(ctlrCfg))
    # Convert raw salt bytes to qb64 format expected by openHby
    saltQb64 = Salter(raw=salt).qb64
    with openHby(salt=saltQb64, name=name, temp=True, cf=cf) as hby:
        hbyDoer = habbing.HaberyDoer(habery=hby)
        anchorer = Anchorer(hby=hby, proxy=None)
        postman = Poster(hby=hby)
        exc = Exchanger(hby=hby, handlers=[])
        notifier = Notifier(hby=hby)
        delegating.loadHandlers(hby=hby, exc=exc, notifier=notifier)
        grouping.loadHandlers(exc=exc, mux=grouping.Multiplexor(hby=hby, notifier=notifier))
        mbx = MailboxDirector(hby=hby, exc=exc, topics=['/receipt', '/replay', '/reply', '/delegate', '/multisig'])
        witReceiptor = WitnessReceiptor(hby=hby)
        receiptor = Receiptor(hby=hby)
        witq = WitnessInquisitor(hby=hby)
        counselor = grouping.Counselor(hby=hby)
        escrowDoer = EscrowDoer(hby=hby, counselor=counselor)
        doers = [hbyDoer, anchorer, postman, mbx, witReceiptor, receiptor, witq, counselor, escrowDoer]
        yield ControllerContext(
            hby=hby,
            doers=doers,
            hbyDoer=hbyDoer,
            anchorer=anchorer,
            postman=postman,
            exc=exc,
            notifier=notifier,
            mbx=mbx,
            witReceiptor=witReceiptor,
            receiptor=receiptor,
            witq=witq,
            counselor=counselor,
        )


# =============================================================================
# Helper Functions
# =============================================================================

class HabHelpers:
    """Static helpers for Hab/Habery operations."""

    @staticmethod
    def generateOobi(hby: Habery, alias: str, role: str = kering.Roles.witness) -> str:
        """Generate an OOBI URL for the given Hab."""
        hab = hby.habByName(name=alias)
        if hab is None:
            raise kering.ConfigurationError(f'Hab with alias {alias} not found in Habery.')

        oobi = ''
        if role in (kering.Roles.witness,):
            if not hab.kever.wits:
                raise kering.ConfigurationError(f'{alias} identifier {hab.pre} does not have any witnesses.')
            for wit in hab.kever.wits:
                urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or hab.fetchUrls(
                    eid=wit, scheme=kering.Schemes.https
                )
                if not urls:
                    raise kering.ConfigurationError(f'unable to query witness {wit}, no http endpoint')
                url = urls[kering.Schemes.https] if kering.Schemes.https in urls else urls[kering.Schemes.http]
                oobi = f'{url.rstrip("/")}/oobi/{hab.pre}/witness'
        elif role in (kering.Roles.controller,):
            urls = hab.fetchUrls(eid=hab.pre, scheme=kering.Schemes.http) or hab.fetchUrls(
                eid=hab.pre, scheme=kering.Schemes.https
            )
            if not urls:
                raise kering.ConfigurationError(f'{alias} identifier {hab.pre} does not have any controller endpoints')
            url = urls[kering.Schemes.https] if kering.Schemes.https in urls else urls[kering.Schemes.http]
            oobi = f'{url.rstrip("/")}/oobi/{hab.pre}/controller'

        if oobi:
            return oobi
        else:
            raise kering.ConfigurationError(f'Unable to generate OOBI for {alias} identifier {hab.pre} with role {role}')

    @staticmethod
    def resolveOobi(doist: Doist, deeds: deque, hby: Habery, oobi: str, alias: str = None):
        """Resolve an OOBI for a given Habery using the provided Doist and deeds."""
        obr = basing.OobiRecord(date=helping.nowIso8601())
        if alias is not None:
            obr.oobialias = alias
        hby.db.oobis.put(keys=(oobi,), val=obr)

        oobiery = oobiing.Oobiery(hby=hby)
        authn = oobiing.Authenticator(hby=hby)
        oobiery_deeds = doist.enter(doers=oobiery.doers + authn.doers)
        while not oobiery.hby.db.roobi.get(keys=(oobi,)):
            # Note: EscrowDoer in controller context handles processEscrows for controller deeds
            # but oobiery_deeds are separate so escrows for those may still need processing
            doist.recur(deeds=decking.Deck(list(deeds) + list(oobiery_deeds)))

    @staticmethod
    def hasDelegables(db: basing.Baser) -> List[Tuple[str, int, bytes]]:
        """Check if there are any delegable events in escrow."""
        dlgs = []
        for (pre, sn), edig in db.delegables.getItemIter():
            dlgs.append((pre, sn, edig))
        return dlgs

    @staticmethod
    def collectWitnessReceipts(doist: Doist, deeds: deque, wit_receiptor, pre: str, sn: int = None):
        """
        Collect witness receipts for an event.

        This queues a request for the WitnessReceiptor to send the event to all
        witnesses and collect their receipts. The actual receipts arrive asynchronously
        via the MailboxDirector which polls the witness mailbox.

        WitnessReceiptor.cues must be cleared after receipts are collected to ensure a clean
        start condition for the next event.

        Parameters:
            doist: The Doist running the event loop
            deeds: The deeds to recur with (should include wit_receiptor's doers)
            wit_receiptor: The WitnessReceiptor instance (from controller context)
            pre: The AID prefix of the identifier to collect receipts for
            sn: Optional sequence number of event (defaults to latest if not provided)
        """
        msg = dict(pre=pre)
        if sn is not None:
            msg['sn'] = sn
        wit_receiptor.msgs.append(msg)
        while not wit_receiptor.cues:
            doist.recur(deeds=deeds)
        wit_receiptor.cues.clear()

    @staticmethod
    def delegationSeal(delegateAid: str, delegateSnh: str, delegateEvtSaid: str):
        """Returns a delegation seal a delegator can use to approve a delegated inception or rotation event."""
        return dict(i=delegateAid, s=delegateSnh, d=delegateEvtSaid)

    @staticmethod
    def clearSentCue(postman: Poster, said: str):
        """
        Remove cue(s) from Poster.cues that match the given SAID.

        This is more precise than postman.cues.clear() because it only removes
        cues for the specific message, leaving other pending send confirmations intact.

        Parameters:
            postman: The Poster instance
            said: The SAID of the message to clear from cues
        """
        # Build new list without matching cues, then replace contents
        remaining = [cue for cue in postman.cues if cue.get("said") != said]
        postman.cues.clear()
        for cue in remaining:
            postman.cues.append(cue)


# =============================================================================
# Orchestration Doers for Multisig
# =============================================================================

class MultisigInceptLeader(doing.DoDoer):
    """
    Similar to `kli multisig incept`.
    Orchestrates multisig inception from the leader's perspective.

    The leader:
    1. Creates the GroupHab with makeGroupHab
    2. Sends /multisig/icp EXN notification to all followers
    3. Starts Counselor to collect signatures
    4. Waits for cgms (confirmed group multisig)

    Counselor completes only when all followers have

    Parameters:
        hby: The Habery for this participant
        mhab: The member Hab (single-sig AID) for this participant
        smids: List of all signing member AIDs (including self)
        rmids: List of all rotation member AIDs (including self)
        group: Name for the new group AID
        isith: Signing threshold
        nsith: Next (rotation) threshold
        toad: Witness threshold
        wits: List of witness prefixes
        delpre: Delegator prefix (if this is a delegated multisig)
        postman: Poster for sending messages
        counselor: Counselor for coordinating multisig
        witReceiptor: WitnessReceiptor for getting receipts
    """

    def __init__(self, hby: Habery, mhab: Hab, smids: List[str], rmids: List[str],
                 group: str, isith: str, nsith: str, toad: int, wits: List[str],
                 postman: Poster, counselor: grouping.Counselor, witReceiptor: WitnessReceiptor,
                 delpre: str = None, **kwa):
        self.hby = hby
        self.mhab = mhab
        self.smids = smids
        self.rmids = rmids
        self.group = group
        self.isith = isith
        self.nsith = nsith
        self.toad = toad
        self.wits = wits
        self.delpre = delpre
        self.postman = postman
        self.counselor = counselor
        self.witReceiptor = witReceiptor
        self.ghab: GroupHab = None
        self.cues = decking.Deck()
        self.done = False
        self.pending_sends = []  # Track SAIDs of messages waiting for delivery confirmation
        self.counselor_started = False

        # Note: postman and counselor are NOT included here because they're already
        # running via the controller context's doers (all_deeds). The CLI's
        # GroupMultisigIncept creates its own instances, but we reuse the existing ones.
        super(MultisigInceptLeader, self).__init__(doers=[], **kwa)

    def recur(self, tyme, deeds=None):
        """Main orchestration loop for leading a multisig inception."""
        super(MultisigInceptLeader, self).recur(tyme, deeds=deeds)

        # Step 1: Create GroupHab and notify followers
        if self.ghab is None:
            self._createGroupHabAndNotifyFollowers()
            return False

        # Step 2: Wait for sends to complete before starting Counselor
        if not self._checkPendingSendsComplete():
            return False

        # Step 3: Start the Counselor (once, after sends complete)
        if not self.counselor_started:
            self._startCounselor()
            return False

        # Step 4: Wait for Counselor to complete (cgms)
        if self._isCounselorComplete():
            self.done = True
            return True

        return False

    def _createGroupHabAndNotifyFollowers(self):
        """Create the GroupHab and send /multisig/icp EXN to all followers."""
        inits = dict(
            isith=self.isith,
            nsith=self.nsith,
            toad=self.toad,
            wits=self.wits,
            delpre=self.delpre,
        )
        self.ghab = self.hby.makeGroupHab(
            group=self.group,
            mhab=self.mhab,
            smids=self.smids,
            rmids=self.rmids,
            **inits
        )

        # Create and send the inception EXN to followers
        icp = self.ghab.makeOwnInception(allowPartiallySigned=True)
        exn, ims = grouping.multisigInceptExn(
            self.mhab,
            smids=self.smids,
            rmids=self.rmids,
            icp=icp
        )

        self._sendToOtherMembers(exn, ims)
        self.pending_sends.append(exn.said)

    def _sendToOtherMembers(self, exn: serdering.SerderKERI, attachment: bytes):
        """Send an EXN message to all other multisig members."""
        others = [m for m in self.smids if m != self.mhab.pre]
        for recpt in others:
            self.postman.send(
                src=self.mhab.pre,
                dest=recpt,
                topic="multisig",
                serder=exn,
                attachment=attachment
            )

    def _checkPendingSendsComplete(self) -> bool:
        """Check if all pending EXN sends have been delivered."""
        if not self.pending_sends:
            return True

        for said in list(self.pending_sends):
            if self.postman.sent(said=said):
                self.pending_sends.remove(said)
                HabHelpers.clearSentCue(self.postman, said)

        return not self.pending_sends

    def _startCounselor(self):
        """Start the Counselor to coordinate signature collection."""
        prefixer = coring.Prefixer(qb64=self.ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=prefixer.qb64)
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=self.ghab)
        self.counselor_started = True

    def _isCounselorComplete(self) -> bool:
        """Check if Counselor has completed signature coordination."""
        prefixer = coring.Prefixer(qb64=self.ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=self.ghab.pre)
        return self.counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)


class MultisigInceptFollower(doing.DoDoer):
    """
    Similar to `kli multisig join`.
    Joins a multisig inception from a follower's perspective.

    The follower:
    1. Waits for /multisig/icp notification (via notifier)
    2. Creates matching GroupHab
    3. Signs and sends signature to others
    4. Starts Counselor to track completion

    Parameters:
        hby: The Habery for this participant
        mhab: The member Hab (single-sig AID) for this participant
        group: Name for the new group AID (must match leader's)
        postman: Poster for sending messages
        counselor: Counselor for coordinating multisig
        notifier: Notifier for receiving EXN messages
        witReceiptor: WitnessReceiptor for getting receipts
        auto: Whether to auto-approve (default True for tests)
    """
    def __init__(self, hby: Habery, mhab: Hab, group: str,
                 postman: Poster, counselor: grouping.Counselor,
                 notifier: Notifier, witReceiptor: WitnessReceiptor,
                 auto: bool = True, **kwa):
        self.hby = hby
        self.mhab = mhab
        self.group = group
        self.postman = postman
        self.counselor = counselor
        self.notifier = notifier
        self.witReceiptor = witReceiptor
        self.auto = auto
        self.ghab: GroupHab = None
        self.started = False
        self.done = False
        self.pendingSends = []  # Track SAIDs of messages waiting for delivery confirmation
        self.counselorStarted = False

        # Note: postman and counselor are NOT included here because they're already
        # running via the controller context's doers (all_deeds).
        super(MultisigInceptFollower, self).__init__(doers=[], **kwa)

    def recur(self, tyme, deeds=None):
        """Main orchestration loop for joining a multisig inception."""
        super(MultisigInceptFollower, self).recur(tyme, deeds=deeds)

        # Step 1: Wait for /multisig/icp notification and create GroupHab
        if self.ghab is None:
            self._processInceptionNotifications()
            return False

        # Step 2: Wait for sends to complete before starting Counselor
        if not self._checkPendingSendsComplete():
            return False

        # Step 3: Start Counselor (once, after sends complete)
        if not self.counselorStarted:
            self._startCounselor()
            return False

        # Step 4: Wait for Counselor to complete
        if self._isCounselorComplete():
            print(f"[Follower {self.mhab.pre[:8]}] Multisig inception complete for {self.ghab.pre}", flush=True)
            self.done = True
            return True

        return False

    def _processInceptionNotifications(self):
        """
        Scan notifications for /multisig/icp and create GroupHab.

        Uses noter.notes (persistent notifications) not signaler.signals
        (transient pings). This pattern matches `kli multisig join`.
        """
        if self.notifier.noter.notes.cntAll() == 0:
            return  # No notifications yet

        for keys, notice in self.notifier.noter.notes.getItemIter():
            if self._processIcpNotification(keys, notice):
                break  # Successfully processed one notification

    def _processIcpNotification(self, keys, notice) -> bool:
        """
        Process a single /multisig/icp notification.

        Returns:
            True if successfully processed, False to skip
        """
        attrs = notice.attrs
        route = attrs['r']

        if route != '/multisig/icp':
            return False  # Not an inception notification

        exnSaid = attrs['d']
        exn, _ = exchanging.cloneMessage(self.hby, said=exnSaid)

        # Extract member info from payload
        payload = exn.ked['a']
        smids = payload['smids']
        rmids = payload['rmids']

        # Verify we're a participant
        if self.mhab.pre not in smids:
            raise ValueError(f"[Follower {self.mhab.pre[:8]}] Not in smids ({self.mhab.pre}), skipping. smids={smids}")

        # Extract inception parameters and create GroupHab
        inits = self._extractInceptionParams(exn)
        self.ghab = self.hby.makeGroupHab(
            group=self.group,
            mhab=self.mhab,
            smids=smids,
            rmids=rmids,
            **inits
        )

        # Remove processed notification
        self.notifier.noter.notes.rem(keys=keys)

        # Send our signature to others
        self._sendSignatureToOthers(smids, rmids)
        return True

    def _extractInceptionParams(self, exn: serdering.SerderKERI) -> dict:
        """Extract GroupHab initialization parameters from the embedded ICP."""
        embeds = exn.ked['e']
        icpKed = embeds['icp']
        origIcp = serdering.SerderKERI(sad=icpKed)

        return dict(
            isith=origIcp.ked["kt"],
            nsith=origIcp.ked["nt"],
            estOnly=kering.TraitCodex.EstOnly in origIcp.ked['c'],
            DnD=kering.TraitCodex.DoNotDelegate in origIcp.ked['c'],
            toad=origIcp.ked["bt"],
            wits=origIcp.ked["b"],
            delpre=origIcp.ked["di"] if "di" in origIcp.ked else None,
        )

    def _sendSignatureToOthers(self, smids: List[str], rmids: List[str]):
        """Create and send our signed inception EXN to other members."""
        icp = self.ghab.makeOwnInception(allowPartiallySigned=True)
        exn, ims = grouping.multisigInceptExn(
            self.mhab,
            smids=smids,
            rmids=rmids,
            icp=icp
        )

        others = [m for m in smids if m != self.mhab.pre]
        for recpt in others:
            self.postman.send(
                src=self.mhab.pre,
                dest=recpt,
                topic="multisig",
                serder=exn,
                attachment=ims
            )
        self.pendingSends.append(exn.said)

    def _checkPendingSendsComplete(self) -> bool:
        """Check if all pending EXN sends have been delivered."""
        if not self.pendingSends:
            return True

        for said in list(self.pendingSends):
            if self.postman.sent(said=said):
                self.pendingSends.remove(said)
                HabHelpers.clearSentCue(self.postman, said)

        return not self.pendingSends

    def _startCounselor(self):
        """Start the Counselor to coordinate signature collection."""
        prefixer = coring.Prefixer(qb64=self.ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=prefixer.qb64)
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=self.ghab)
        self.counselorStarted = True

    def _isCounselorComplete(self) -> bool:
        """Check if Counselor has completed signature coordination."""
        prefixer = coring.Prefixer(qb64=self.ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=self.ghab.pre)
        return self.counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider)


class MultisigDelegationApprover(doing.DoDoer):
    """
    Approves delegation requests for a multisig delegator.

    This coordinates both members of the delegator multisig to:
    1. Watch the delegables escrow for delegation requests
    2. Create anchor events via interact (leader) or wait for coordination (follower)
    3. Coordinate signature collection
    4. Propagate to witnesses

    Parameters:
        hby: The Habery for this delegator participant
        ghab: The GroupHab for the delegator multisig
        mhab: The member Hab for this participant
        counselor: Counselor for coordinating multisig
        witReceiptor: WitnessReceiptor for getting receipts
        witq: WitnessInquisitor for querying witnesses
        postman: Poster for sending messages
        notifier: Notifier for receiving messages (follower mode)
        interact: Whether to use interact (True) or rotate (False) for anchor
        auto: Whether to auto-approve all delegation requests
        leader: Whether this participant is the leader (creates events)
    """

    def __init__(self, hby: Habery, ghab: GroupHab, mhab: Hab,
                 counselor: grouping.Counselor, witReceiptor: WitnessReceiptor,
                 witq: WitnessInquisitor, postman: Poster,
                 notifier: Notifier = None,
                 interact: bool = True, auto: bool = True, leader: bool = True, **kwa):
        self.hby = hby
        self.ghab = ghab
        self.mhab = mhab
        self.counselor = counselor
        self.witReceiptor = witReceiptor
        self.witq = witq
        self.postman = postman
        self.notifier = notifier
        self.interact = interact
        self.auto = auto
        self.leader = leader
        self.approved = set()  # Track approved delegation (pre, sn) tuples
        # Track pending sends: {(pre, sn): {'said': exn_said, 'ixn_sn': sn, 'ixn_said': said}}
        self.pendingSends = {}
        # Track delegations ready for counselor start
        self.readyForCounselor = {}
        # Track delegations waiting for counselor completion
        # {(pre, sn): {'ixn_sn': int, 'ixn_said': str, 'edig': bytes}}
        self.waitingForComplete = {}

        # Note: counselor and postman are NOT included here because they're already
        # running via the controller context's doers (all_deeds).
        super(MultisigDelegationApprover, self).__init__(doers=[], **kwa)

    def delegablesEscrowed(self) -> List[Tuple[str, int, bytes]]:
        """Get list of delegable events in escrow."""
        return [(pre, sn, edig) for (pre, sn), edig in self.hby.db.delegables.getItemIter()]

    def recur(self, tyme, deeds=None):
        """
        Main orchestration loop for delegation approval.

        The approval process flows through these stages:
        1. Leader finds delegables → creates anchor → sends EXN to followers
        2. Followers receive EXN notification → sign same anchor → send EXN back
        3. Counselor coordinates signatures across all participants
        4. Once complete, release escrowed delegation by reprocessing with seal
        """
        super(MultisigDelegationApprover, self).recur(tyme, deeds=deeds)

        # Process the approval pipeline
        self._processPendingSends()
        self._startCounselorForReadyDelegations()
        self._releaseCompletedDelegations()

        # Leader creates anchors, follower signs from notifications
        if self.leader:
            self._leaderProcessDelegables()
        else:
            self._followerProcessNotifications()

        return False  # Keep running

    def _processPendingSends(self):
        """
        Check for EXN messages that have been successfully delivered.

        After the leader sends an anchor proposal to followers, we wait for
        postman to confirm delivery before starting the Counselor coordination.
        """
        for key in list(self.pendingSends.keys()):
            info = self.pendingSends[key]
            if self.postman.sent(said=info['said']):
                self.readyForCounselor[key] = info
                del self.pendingSends[key]
                HabHelpers.clearSentCue(self.postman, info['said'])

    def _startCounselorForReadyDelegations(self):
        """
        Start Counselor coordination for delegations that are ready.

        The Counselor collects signatures from all multisig participants
        and marks the event complete when threshold is met.
        """
        for key in list(self.readyForCounselor.keys()):
            info = self.readyForCounselor[key]
            prefixer = coring.Prefixer(qb64=self.ghab.pre)
            seqner = coring.Seqner(sn=info['ixn_sn'])
            saider = coring.Saider(qb64=info['ixn_said'])

            self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=self.ghab)
            self.waitingForComplete[key] = info
            print(f"[DelegationApprover {self.mhab.pre[:8]}] Started counselor for anchor at sn={info['ixn_sn']}")
            del self.readyForCounselor[key]

    def _releaseCompletedDelegations(self):
        """
        Release escrowed delegations after anchor coordination completes.

        This is necessary because the delegables escrow has no automatic processor.
        Delegation approval is an active policy decision (like `kli delegate confirm`).

        Once the multisig anchor is complete, we:
        1. Save the authorizer seal (AES) so processEscrowDelegables can find it
        2. Reprocess the escrowed DIP/DRT via processEscrowDelegables
        3. Remove it from the delegables escrow
        """
        for key in list(self.waitingForComplete.keys()):
            info = self.waitingForComplete[key]
            prefixer = coring.Prefixer(qb64=self.ghab.pre)
            seqner = coring.Seqner(sn=info['ixn_sn'])

            if not self.counselor.complete(prefixer=prefixer, seqner=seqner):
                continue

            self._setAuthorizerSeal(key, info)
            self._releaseEscrowedDelegation(key)
            self.approved.add(key)
            del self.waitingForComplete[key]

    def _setAuthorizerSeal(self, key: Tuple[str, str], info: dict):
        """
        Save the authorizer (delegator) event seal for the escrowed delegated event.

        AES maps: dgKey(delegate_pre, delegate_event_dig) -> (delegator_anchor_sn + delegator_anchor_said)

        This must be set BEFORE calling processEscrowDelegables() so the escrow
        processor can find the seal and successfully reprocess the event.

        Args:
            key: (delegate_pre, delegate_sn) tuple identifying the escrowed event
            info: dict with 'ixn_sn' and 'ixn_said' for the delegator's anchor event
        """
        (pre, sn) = key
        for dpre, dsn, edig in self.delegablesEscrowed():
            if dpre == pre and dsn == sn:
                dgkey = dbing.dgKey(pre, edig)
                seqner = coring.Seqner(sn=info['ixn_sn'])
                saider = coring.Saider(qb64=info['ixn_said'])
                couple = seqner.qb64b + saider.qb64b
                self.hby.db.setAes(dgkey, couple)
                break

    def _releaseEscrowedDelegation(self, key: Tuple[str, str]):
        """
        Release an escrowed DIP/DRT event via processEscrowDelegables.

        The AES seal must already be set (via _setAuthorizerSeal) before calling this.

        Args:
            key: (delegate_pre, delegate_sn) tuple identifying the escrowed event
        """
        self.hby.kvy.processEscrowDelegables()
        (pre, _sn) = key
        print(f"[DelegationApprover {self.mhab.pre[:8]}] Released delegation for {pre[:8]} from escrow")

    def _leaderProcessDelegables(self):
        """
        Leader: Find delegable events and create anchor proposals.

        The leader is responsible for:
        1. Scanning the delegables escrow for DIP/DRT events we need to approve
        2. Creating an IXN anchor event with the delegation seal
        3. Sending a /multisig/ixn EXN to all other multisig members
        """
        for pre, sn, edig in self.delegablesEscrowed():
            key = (pre, sn)
            if self._isAlreadyProcessing(key):
                continue

            eserder = self._getValidDelegableEvent(pre, edig)
            if eserder is None:
                continue

            if not self.auto:
                continue

            self._createAndSendAnchor(key, eserder)

    def _isAlreadyProcessing(self, key: Tuple[str, str]) -> bool:
        """Check if this delegation is already being processed."""
        return (key in self.approved or
                key in self.pendingSends or
                key in self.readyForCounselor or
                key in self.waitingForComplete)

    def _getValidDelegableEvent(self, pre: str, edig: bytes) -> serdering.SerderKERI:
        """
        Get a delegable event if it's a valid DIP/DRT for our multisig.

        Returns:
            SerderKERI if valid, None otherwise
        """
        dgkey = dbing.dgKey(pre, edig)
        eraw = self.hby.db.getEvt(dgkey)
        if eraw is None:
            return None

        eserder = serdering.SerderKERI(raw=bytes(eraw))
        ilk = eserder.sad['t']

        # Must be a delegated event
        if ilk not in (coring.Ilks.dip, coring.Ilks.drt):
            return None

        # Get the delegator prefix
        if ilk == coring.Ilks.dip:
            delpre = eserder.sad['di']
        else:  # drt
            dkever = self.hby.kevers[eserder.pre]
            delpre = dkever.delpre

        # We must be the delegator
        if delpre != self.ghab.pre:
            return None

        return eserder

    def _createAndSendAnchor(self, key: Tuple[str, str], eserder: serdering.SerderKERI):
        """
        Create an anchor IXN and send /multisig/ixn EXN to other members.

        Args:
            key: (delegate_pre, delegate_sn) tuple
            eserder: The delegated event to approve
        """
        print(f"[DelegationApprover {self.mhab.pre[:8]}] Found delegable {eserder.sad['t']} event for {eserder.pre[:8]}")

        # Create the delegation seal
        anchor = HabHelpers.delegationSeal(eserder.ked['i'], eserder.snh, eserder.said)

        if not self.interact:
            raise ValueError(f"[DelegationApprover {self.mhab.pre[:8]}] delegation approval via rotation not yet supported")

        # Create the anchor IXN (signs and stores locally)
        ixn = self.ghab.interact(data=[anchor])
        ixnser = serdering.SerderKERI(raw=ixn)

        # Create and send the multisig coordination EXN
        exn, ims = grouping.multisigInteractExn(
            ghab=self.ghab,
            aids=self.ghab.smids,
            ixn=ixn
        )

        self._sendToOtherMembers(exn, ims) # sends exn notification to other members (followers)

        # Track for delivery confirmation
        self.pendingSends[key] = {
            'said': exn.said,
            'ixn_sn': ixnser.sn,
            'ixn_said': ixnser.said
        }
        print(f"[DelegationApprover {self.mhab.pre[:8]}] Created anchor for {eserder.pre[:8]} at sn={ixnser.sn}, waiting for send confirmation")

    def _sendToOtherMembers(self, exn: serdering.SerderKERI, attachment: bytes):
        """Send an EXN message to all other multisig members."""
        others = [m for m in self.ghab.smids if m != self.mhab.pre]
        for recpt in others:
            self.postman.send(
                src=self.mhab.pre,
                dest=recpt,
                topic="multisig",
                serder=exn,
                attachment=attachment
            )

    def _followerProcessNotifications(self):
        """
        Follower: Listen for /multisig/ixn notifications and co-sign the anchor.

        When the leader creates an anchor, they send a /multisig/ixn EXN to
        all other members. The follower:
        1. Receives the notification via the Notifier
        2. Extracts the IXN data (which contains the delegation seal)
        3. Creates the SAME IXN locally (this signs it)
        4. Sends their own /multisig/ixn EXN back to coordinate signatures
        5. Starts the Counselor to complete coordination
        """
        if self.notifier is None:
            return

        for keys, notice in self.notifier.noter.notes.getItemIter():
            result = self._processIxnNotification(keys, notice)
            if result:
                # Successfully processed, remove the notification
                self.notifier.noter.notes.rem(keys=keys)

    def _processIxnNotification(self, keys, notice) -> bool:
        """
        Process a single /multisig/ixn notification.

        Returns:
            True if successfully processed, False to skip
        """
        attrs = notice.attrs
        route = attrs.get('r')

        if route != '/multisig/ixn':
            return False

        said = attrs.get('d')  # EXN SAID
        if said is None:
            return False

        # Get the EXN message
        exn, _ = exchanging.cloneMessage(self.hby, said=said)
        if exn is None:
            return False

        # Verify this is for our multisig group
        payload = exn.ked.get('a', {})
        gid = payload.get('gid')
        if gid != self.ghab.pre:
            return False

        # Extract the embedded IXN data
        embeds = exn.ked.get('e', {})
        ixn_data = embeds.get('ixn', {})
        if not ixn_data:
            return False

        # Extract delegation info from the anchor seal
        delegate_info = self._extractDelegateInfoFromAnchor(ixn_data)
        if delegate_info is None:
            return False

        delegate_pre, delegate_sn, anchor_data = delegate_info

        # Sign and coordinate
        self._signAndCoordinateAnchor(delegate_pre, delegate_sn, anchor_data)
        return True

    def _extractDelegateInfoFromAnchor(self, ixn_data: dict) -> Tuple[str, str, list]:
        """
        Extract delegate prefix and sn from the anchor's seal data.

        The anchor IXN contains seals like: {'i': delegate_pre, 's': delegate_sn, 'd': delegate_said}

        Returns:
            (delegate_pre, delegate_sn, anchor_data) or None if not found
        """
        oixnser = serdering.SerderKERI(sad=ixn_data)
        data = oixnser.ked.get('a', [])

        for seal in data:
            if isinstance(seal, dict) and 'i' in seal and 's' in seal:
                delegate_pre = seal['i']
                # Convert to 32-char hex string to match db.delegables key format
                sn_int = int(seal['s'], 16) if isinstance(seal['s'], str) else seal['s']
                delegate_sn = f"{sn_int:032x}"
                return (delegate_pre, delegate_sn, data)

        return None

    def _signAndCoordinateAnchor(self, delegate_pre: str, delegate_sn: str, anchor_data: list):
        """
        Create the same anchor IXN locally and start coordination.

        By calling ghab.interact() with the same data, we create an event
        with the same SAID as the leader's, which allows signature aggregation.
        """
        # Create the SAME interaction event (this signs it locally)
        ixn = self.ghab.interact(data=anchor_data)
        ixnser = serdering.SerderKERI(raw=ixn)

        # Send our signing notification to others
        exn_out, ims = grouping.multisigInteractExn(
            ghab=self.ghab,
            aids=self.ghab.smids,
            ixn=ixn
        )
        self._sendToOtherMembers(exn_out, ims)

        # Start Counselor coordination
        prefixer = coring.Prefixer(qb64=self.ghab.pre)
        seqner = coring.Seqner(sn=ixnser.sn)
        saider = coring.Saider(qb64=ixnser.said)
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=self.ghab)

        # Track for completion (key must match delegables format)
        self.waitingForComplete[(delegate_pre, delegate_sn)] = {
            'ixn_sn': ixnser.sn,
            'ixn_said': ixnser.said
        }

        print(f"[DelegationApprover {self.mhab.pre[:8]}] Signed anchor from leader at sn={ixnser.sn} for delegate {delegate_pre[:8]}", flush=True)


class KeystateQueryDoer(doing.Doer):
    """
    Queries for keystate to discover delegation approval anchor.

    Parameters:
        hby: The Habery making the query
        hab: The Hab making the query (source)
        target_pre: The prefix to query for
        target_sn: The sequence number to wait for (optional)
        witq: WitnessInquisitor for making queries
        wits: List of witness prefixes to query
    """

    def __init__(self, hby: Habery, hab: Hab, target_pre: str,
                 witq: WitnessInquisitor, wits: List[str] = None,
                 target_sn: int = None, **kwa):
        self.hby = hby
        self.hab = hab
        self.target_pre = target_pre
        self.target_sn = target_sn
        self.witq = witq
        self.wits = wits or []
        self.queried = False
        super(KeystateQueryDoer, self).__init__(**kwa)

    def recur(self, tyme, deeds=None):
        """Query and wait for keystate."""
        if not self.queried:
            self._sendQuery()

        if self._hasRequiredKeystate():
            return True

        return False

    def _sendQuery(self):
        """Send the keystate query to witnesses."""
        self.witq.query(src=self.hab.pre, pre=self.target_pre, wits=self.wits)
        self.queried = True
        print(f"[KeystateQuery] Querying for {self.target_pre[:8]}")

    def _hasRequiredKeystate(self) -> bool:
        """Check if we have the required keystate."""
        if self.target_pre not in self.hby.kevers:
            return False

        kever = self.hby.kevers[self.target_pre]
        if self.target_sn is not None and kever.sn < self.target_sn:
            return False

        print(f"[KeystateQuery] Found keystate for {self.target_pre[:8]} at sn={kever.sn}")
        return True
