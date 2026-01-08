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
from keri.core import Salter, coring, serdering
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
        """Main orchestration loop."""
        super(MultisigInceptLeader, self).recur(tyme, deeds=deeds)

        if self.ghab is None:
            # Step 1: Create the GroupHab
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

            # Step 2: Create and send the inception EXN to followers
            icp = self.ghab.makeOwnInception(allowPartiallySigned=True)
            exn, ims = grouping.multisigInceptExn(
                self.mhab,
                smids=self.smids,
                rmids=self.rmids,
                icp=icp
            )

            # Send to all other participants and track for delivery confirmation
            others = [m for m in self.smids if m != self.mhab.pre]
            for recpt in others:
                self.postman.send(
                    src=self.mhab.pre,
                    dest=recpt,
                    topic="multisig",
                    serder=exn,
                    attachment=ims
                )
            self.pending_sends.append(exn.said)  # Track SAID for delivery confirmation
            return False  # Keep running

        # Step 3: Wait for sends to complete before starting Counselor
        if self.pending_sends:
            for said in list(self.pending_sends):
                if self.postman.sent(said=said):
                    self.pending_sends.remove(said)
            if self.pending_sends:
                return False  # Still waiting for sends to complete
            self.postman.cues.clear()  # Clear cues after all sends confirmed

        # Step 4: Start the Counselor (once, after sends complete)
        if not self.counselor_started:
            prefixer = coring.Prefixer(qb64=self.ghab.pre)
            seqner = coring.Seqner(sn=0)
            saider = coring.Saider(qb64=prefixer.qb64)
            self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=self.ghab)
            self.counselor_started = True
            return False  # Keep running

        # Step 5: Wait for Counselor to complete (cgms)
        # Note: EscrowDoer in controller context handles processEscrows calls
        prefixer = coring.Prefixer(qb64=self.ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=self.ghab.pre)
        if self.counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider):
            self.done = True
            return True  # Done

        return False  # Keep running


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
        """Main orchestration loop."""
        super(MultisigInceptFollower, self).recur(tyme, deeds=deeds)

        if self.ghab is None:
            # Wait for notification from leader using noter.notes (persistent notifications)
            # not signaler.signals (transient pings). Pattern from kli multisig join.
            if self.notifier.noter.notes.cntAll() == 0:
                return False  # No notifications yet, keep waiting
            
            for keys, notice in self.notifier.noter.notes.getItemIter():
                attrs = notice.attrs
                route = attrs['r']
                
                if route != '/multisig/icp':
                    print(f"[Follower {self.mhab.pre[:8]}] Not an inception notification - only care about inception notifications for this follower", flush=True)
                    continue  # Not an inception notification - only care about inception notifications for this follower
                
                exnSaid = attrs['d']
                exn, _ = exchanging.cloneMessage(self.hby, said=exnSaid)

                payload = exn.ked['a']
                smids = payload['smids']
                rmids = payload['rmids']

                # Check if we're a participant
                if self.mhab.pre not in smids:
                    raise ValueError(f"[Follower {self.mhab.pre[:8]}] Not in smids ({self.mhab.pre}), skipping. smids={smids}")

                # Get the embedded icp event from the EXN
                embeds = exn.ked['e']
                icpKed = embeds['icp']
                origIcp = serdering.SerderKERI(sad=icpKed)

                # Extract parameters from the ICP
                inits = dict(
                    isith=origIcp.ked["kt"],
                    nsith=origIcp.ked["nt"],
                    estOnly=kering.TraitCodex.EstOnly in origIcp.ked['c'],
                    DnD=kering.TraitCodex.DoNotDelegate in origIcp.ked['c'],
                    toad=origIcp.ked["bt"],
                    wits=origIcp.ked["b"],
                    delpre=origIcp.ked["di"] if "di" in origIcp.ked else None,
                )

                # Create our GroupHab
                self.ghab = self.hby.makeGroupHab(
                    group=self.group,
                    mhab=self.mhab,
                    smids=smids,
                    rmids=rmids,
                    **inits
                )

                # Remove the notification now that we've processed it
                self.notifier.noter.notes.rem(keys=keys)

                # Send our signature to others and track for delivery confirmation
                icp = self.ghab.makeOwnInception(allowPartiallySigned=True)
                exn, ims = grouping.multisigInceptExn(
                    self.mhab,
                    smids=smids,
                    rmids=rmids,
                    icp=icp
                )

                others = [m for m in smids if m != self.mhab.pre]
                for recpt in others:
                    # Remember, the Postman is already created in the controller context's doers (all_deeds) and is run
                    # by the controller context's doers.
                    self.postman.send(
                        src=self.mhab.pre,
                        dest=recpt,
                        topic="multisig",
                        serder=exn,
                        attachment=ims
                    )
                self.pendingSends.append(exn.said)  # Track SAID for delivery confirmation
                break  # Exit notification loop after processing

            return False  # Keep running

        # Step 2: Wait for sends to complete before starting Counselor
        if self.pendingSends:
            for said in list(self.pendingSends):
                if self.postman.sent(said=said):
                    self.pendingSends.remove(said)
            if self.pendingSends:
                return False  # Still waiting for sends to complete
            self.postman.cues.clear()  # Clear cues after all sends confirmed

        # Step 3: Start Counselor (once, after sends complete)
        if not self.counselorStarted:
            prefixer = coring.Prefixer(qb64=self.ghab.pre)
            seqner = coring.Seqner(sn=0)
            saider = coring.Saider(qb64=prefixer.qb64)
            self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=self.ghab)
            self.counselorStarted = True
            return False  # Keep running

        # Step 4: Wait for Counselor to complete
        # Note: EscrowDoer in controller context handles processEscrows calls
        prefixer = coring.Prefixer(qb64=self.ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=self.ghab.pre)
        if self.counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider):
            print(f"[Follower {self.mhab.pre[:8]}] Multisig inception complete for {self.ghab.pre}", flush=True)
            self.done = True
            return True  # Done

        return False  # Keep running


class MultisigDelegationApprover(doing.DoDoer):
    """
    Approves delegation requests for a multisig delegator.

    This coordinates both members of the delegator multisig to:
    1. Watch the delegables escrow for delegation requests
    2. Create anchor events via interact
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
        interact: Whether to use interact (True) or rotate (False) for anchor
        auto: Whether to auto-approve all delegation requests
    """

    def __init__(self, hby: Habery, ghab: GroupHab, mhab: Hab,
                 counselor: grouping.Counselor, witReceiptor: WitnessReceiptor,
                 witq: WitnessInquisitor, postman: Poster,
                 interact: bool = True, auto: bool = True, **kwa):
        self.hby = hby
        self.ghab = ghab
        self.mhab = mhab
        self.counselor = counselor
        self.witReceiptor = witReceiptor
        self.witq = witq
        self.postman = postman
        self.interact = interact
        self.auto = auto
        self.approved = set()  # Track approved delegation (pre, sn) tuples
        # Track pending sends: {(pre, sn): {'said': exn_said, 'ixn_sn': sn, 'ixn_said': said}}
        self.pendingSends = {}
        # Track delegations ready for counselor start
        self.readyForcounselor = {}

        # Note: counselor and postman are NOT included here because they're already
        # running via the controller context's doers (all_deeds).
        super(MultisigDelegationApprover, self).__init__(doers=[], **kwa)

    def delegablesEscrowed(self) -> List[Tuple[str, int, bytes]]:
        """Get list of delegable events in escrow."""
        return [(pre, sn, edig) for (pre, sn), edig in self.hby.db.delegables.getItemIter()]

    def recur(self, tyme, deeds=None):
        """Main orchestration loop."""
        super(MultisigDelegationApprover, self).recur(tyme, deeds=deeds)

        # Step 1: Check for pending sends that have completed
        for key in list(self.pendingSends.keys()):
            info = self.pendingSends[key]
            if self.postman.sent(said=info['said']):
                # Send complete, move to ready_for_counselor
                self.readyForcounselor[key] = info
                del self.pendingSends[key]
                self.postman.cues.clear()  # Clear cues after send confirmed

        # Step 2: Start counselor for delegations that are ready
        for key in list(self.readyForcounselor.keys()):
            info = self.readyForcounselor[key]
            prefixer = coring.Prefixer(qb64=self.ghab.pre)
            seqner = coring.Seqner(sn=info['ixn_sn'])
            saider = coring.Saider(qb64=info['ixn_said'])
            self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=self.ghab)
            self.approved.add(key)
            print(f"[DelegationApprover {self.mhab.pre[:8]}] Started counselor for anchor at sn={info['ixn_sn']}")
            del self.readyForcounselor[key]

        # Step 3: Process new delegables
        dlgs = self.delegablesEscrowed()
        for pre, sn, edig in dlgs:
            key = (pre, sn)
            if key in self.approved or key in self.pendingSends or key in self.readyForcounselor:
                continue

            dgkey = dbing.dgKey(pre, edig)
            eraw = self.hby.db.getEvt(dgkey)
            if eraw is None:
                continue

            eserder = serdering.SerderKERI(raw=bytes(eraw))
            ilk = eserder.sad['t']

            if ilk not in (coring.Ilks.dip, coring.Ilks.drt):
                continue

            # Get the delegator prefix
            if ilk == coring.Ilks.dip:
                delpre = eserder.sad['di']
            else:  # drt
                dkever = self.hby.kevers[eserder.pre]
                delpre = dkever.delpre

            # Check if we are the delegator
            if delpre != self.ghab.pre:
                continue

            print(f"[DelegationApprover {self.mhab.pre[:8]}] Found delegable {ilk} event for {eserder.pre[:8]}")

            if self.auto:
                # Create the anchor
                anchor = HabHelpers.delegationSeal(eserder.ked['i'], eserder.snh, eserder.said)

                if self.interact:
                    ixn = self.ghab.interact(data=[anchor])
                else:
                    raise ValueError(f"[DelegationApprover {self.mhab.pre[:8]}] delegation approval not yet supported for rotation events")

                # Create and send multisig IXN EXN to other members
                ixnser = serdering.SerderKERI(raw=ixn)
                exn, ims = grouping.multisigInteractExn(
                    ghab=self.ghab,
                    aids=self.ghab.smids,
                    ixn=ixn
                )

                others = [m for m in self.ghab.smids if m != self.mhab.pre]
                for recpt in others:
                    self.postman.send(
                        src=self.mhab.pre,
                        dest=recpt,
                        topic="multisig",
                        serder=exn,
                        attachment=ims
                    )

                # Track this send for delivery confirmation
                self.pendingSends[key] = {
                    'said': exn.said,
                    'ixn_sn': ixnser.sn,
                    'ixn_said': ixnser.said
                }
                print(f"[DelegationApprover {self.mhab.pre[:8]}] Created anchor for {eserder.pre[:8]} at sn={ixnser.sn}, waiting for send confirmation")

        return False  # Keep running forever


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
            self.witq.query(src=self.hab.pre, pre=self.target_pre, wits=self.wits)
            self.queried = True
            print(f"[KeystateQuery] Querying for {self.target_pre[:8]}")

        # Check if we have the keystate
        if self.target_pre in self.hby.kevers:
            kever = self.hby.kevers[self.target_pre]
            if self.target_sn is None or kever.sn >= self.target_sn:
                print(f"[KeystateQuery] Found keystate for {self.target_pre[:8]} at sn={kever.sn}")
                return True

        return False