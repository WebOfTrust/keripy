# -*- encoding: utf-8 -*-
"""
keri.acdc.regeventing module

Registry (TEL) event support

Shared TEL support for ACDC v2 blindable state registries made of 'rip'
(registry inception) and 'bup' (blindable update) events.

This module now holds three closely related concerns:

1. Verifier-side evidence vetting through vet() and the vet* helpers. Given a
   supplied registry event chain, the issuer's KEL evidence, and optionally a
   disclosed blinded-state block, these functions determine the registry's
   verified state. They fetch nothing and conclude only from the evidence
   handed to them; KEL verification remains the caller's job.
2. Shared TEL validation and anchor helpers reused across verifier and issuer
   flows so registry-event rules live in one place.
3. The private issuer-side local event engine used by registraring.py to
   process, anchor, escrow, replay, and accept TEL events for registries the
   local habitat controls.

In short, regeventing.py owns the TEL-specific validation and event workflow.
"""

from collections.abc import Mapping
from collections import namedtuple

from .. import help
from ..kering import (Ilks, ValidationError, ConfigurationError,
                      InvalidValueError,
                      MissingAnchorError, MisdigestError, MissequenceError,
                      MisregistryError, MisanchorError, RootSealError,
                      MisbindingError, DuplicitousRegistryError,
                      UnverifiedBlindError)
from ..core import Blinder, BlindState, BoundState, Diger, Number, SerderACDC
from . import messaging

logger = help.ogler.getLogger()


RegStateRecord = namedtuple("RegStateRecord",
                            "regid issuer said sn ilk acdc state stamp "
                            "binding anchors")
"""Verified state of a registry (TEL) as determined by vet().

Fields:
    regid (str): qb64 registry SAID (the rip event's said)
    issuer (str): qb64 AID of the registry's issuer (the rip's i field)
    said (str): qb64 SAID of the head (latest verified) registry event
    sn (int): sequence number of the head event
    ilk (str): message type of the head event (rip or bup)
    acdc (str|None): qb64 SAID of the transaction ACDC the head state
        commits to; None when the registry has no update yet or the head is
        blinded and undisclosed
    state (str|None): transaction state string at the head; None when the
        registry has no update yet or the head is blinded and undisclosed
    stamp (str): the head event's issuer-relative ISO datetime (dt field)
    binding (str|None): how the presented ACDC binds to the registry:
        'mutual' when td == acdc.d and acdc.rd == rip.d both hold, 'oneway'
        when the ACDC carries no rd so only the registry commits to the ACDC
        (registry->ACDC), None when no ACDC was presented
    anchors (tuple): one (sn, said) couple per verified chain event, the
        issuer KEL event in which that TEL event's anchoring seal was found
"""

# Shared TEL records
_RegEventRecord = namedtuple("_RegEventRecord",
                             "serder said ilk regk sn prior issuer")
"""Normalized TEL event facts reused across issuer and verifier flows.

Fields:
    serder (SerderACDC): parsed registry event serder
    said (str): qb64 SAID of the event
    ilk (str): registry event type, currently ``rip`` or ``bup``
    regk (str): qb64 registry identifier for the event's TEL
    sn (int): sequence number of the event
    prior (str|None): prior-event SAID for updates, else None for inception
    issuer (str|None): qb64 issuer AID carried by the event when present
"""


# Shared TEL validation kernel
def _coerce(evt):
    """Coerce evt to SerderACDC.  Accepts a SerderACDC instance or raw
    serialized bytes/str (one event's serialization).

    Returns:
        serder (SerderACDC): the coerced event
    """
    if isinstance(evt, SerderACDC):
        return evt
    if isinstance(evt, str):
        evt = evt.encode()
    if isinstance(evt, (bytes, bytearray, memoryview)):
        return SerderACDC(raw=bytes(evt))
    raise InvalidValueError(f"Invalid registry event material type "
                            f"{type(evt)}: expected SerderACDC or raw bytes.")


def _normalizeEventRecord(evt):
    """Normalize one TEL event into a parsed record

    Parameters:
        evt (SerderACDC | bytes | str): registry event material to normalize.

    Returns:
        _RegEventRecord: normalized TEL event facts shared across the issuer
            and verifier flows.

    Raises:
        InvalidValueError: if ``evt`` cannot be coerced into a
            ``SerderACDC``.
        ValidationError: if the event's ``ilk`` is not one of the supported
            v2 registry event types.
    """
    
    # Parse once so every later step reads the same regk/sn/prior/issuer
    serder = _coerce(evt)
    ilk = serder.ilk

    # The v2 ACDC TEL only supports registry inception and blind updates
    if ilk not in (Ilks.rip, Ilks.bup):
        raise ValidationError(f"Unsupported registry event type {ilk} for "
                              f"event {serder.said}.")
    return _RegEventRecord(serder=serder,
                           said=serder.said,
                           ilk=ilk,
                           # For a rip the registry id is the event's own SAID;
                           # for a bup it is carried in rd.
                           regk=serder.said if ilk == Ilks.rip else serder.sad['rd'],
                           sn=Number(numh=serder.sad['n']).num,
                           prior=None if ilk == Ilks.rip else serder.sad['p'],
                           issuer=serder.sad.get('i'))


def _validateRip(evt, *, issuer=None):
    """Validate one registry inception event against shared TEL rules.

    Parameters:
        evt (SerderACDC | bytes | str): registry inception event to validate.
        issuer (str | None): optional expected issuer AID for the inception.

    Returns:
        _RegEventRecord: normalized facts for the validated inception event.

    Raises:
        ValidationError: if the event is not a ``rip`` or the issuer does not
            match the expected local or presented issuer.
        MissequenceError: if the inception event is not at sequence number
            ``n = 0``.
    """

    # Normalize the event first so regk, sn, and issuer are interpreted consistently
    event = _normalizeEventRecord(evt)

    # Raise if the event is not a rip
    if event.ilk != Ilks.rip:
        raise ValidationError(f"Expected registry inception ilk={Ilks.rip} "
                              f"got ilk={event.ilk} for event "
                              f"{event.said}.")

    # Validate correct sequence number for a rip
    if event.sn != 0:
        raise MissequenceError(f"Registry inception {event.said} has "
                               f"n={event.serder.sad['n']} but inception "
                               f"must be at n=0.")

    # Validate the issuer is the same as the one provided
    if issuer is not None and event.issuer != issuer:
        raise ValidationError(f"Registry inception event {event.said} has "
                              f"invalid issuer {event.issuer}.")
    return event


def _validateUpdate(evt, *, regid, prior=None):
    """Validate one blindable registry update against shared TEL rules.

    Parameters:
        evt (SerderACDC | bytes | str): registry update event to validate.
        regid (str): expected qb64 registry identifier for the update.
        prior (str | None): optional expected prior-event SAID when the caller
            already knows the accepted predecessor.

    Returns:
        _RegEventRecord: normalized facts for the validated update event.

    Raises:
        ValidationError: if the event is not a ``bup``.
        MisregistryError: if the update names a different registry.
        MissequenceError: if the update is not at sequence number ``n >= 1``.
        MisdigestError: if the update's ``p`` field does not match the
            provided predecessor.
    """

    # Normalize first so regid, sn, and prior are interpreted consistently.
    event = _normalizeEventRecord(evt)

    # Only blindable updates belong in this path
    if event.ilk != Ilks.bup:
        raise ValidationError(f"Expected registry update ilk={Ilks.bup} got "
                              f"ilk={event.ilk} for event {event.said}.")

    # Validate the registry id matches the one provided
    if event.regk != regid:
        raise MisregistryError(f"Registry update {event.said} has "
                               f"rd={event.regk} which is not the "
                               f"presented registry inception's said "
                               f"{regid}.")

    # sn 0 is reserved for the rip, so updates start at one.
    if event.sn < 1:
        raise MissequenceError(f"Registry update {event.said} has "
                               f"n={event.serder.sad['n']} but updates must "
                               f"be at n >= 1.")

    # When a caller already knows the prior, require the chain link to
    # match before any deeper processing happens.
    if prior is not None and event.prior != prior:
        raise MisdigestError(f"Registry event {event.said} at n={event.sn} "
                             f"has p={event.prior} which is not the prior "
                             f"event's said {prior}.")
    return event


# Shared KEL anchor primitives
def _kever(db, pre):
    """Return the Kever for pre from db's read-through kevers cache, or None
    when the KEL is not available."""
    try:
        return db.kevers[pre]
    except KeyError:
        return None


def _kelEvent(db, pre, claim):
    """Resolve a claimed anchoring key event of pre's KEL by sequence number
    (int) or SAID (str).  Returns the event serder or None when absent."""
    if isinstance(claim, int):
        dig = db.kels.getLast(keys=pre, on=claim)
        if dig is None:
            return None
        return db.evts.get(keys=(pre, dig))
    return db.evts.get(keys=(pre, claim))


def sealDigests(serder):
    """Extract the candidate seal digests from a key event's seal data list.

    A seal may be as simple as the sealed event's SAID (a bare digest
    string), or a mapping bearing a 'd' field, with or without an 's'
    sequence-number hint.  The hint is never load-bearing: matching is by
    digest only, so a wrong or absent 's' does not disqualify a seal.

    Returns:
        digs (list[str]): qb64 seal digests found in serder's 'a' field
    """
    seals = serder.sad.get('a') or ()
    digs = []
    if isinstance(seals, (list, tuple)):
        for seal in seals:
            if isinstance(seal, str):
                digs.append(seal)
            elif isinstance(seal, Mapping) and 'd' in seal:
                digs.append(seal['d'])
    return digs


def _scanKel(db, pre, said):
    """Scan the KEL of pre in db for a key event whose seals include a digest
    equal to said.

    Returns:
        couple (tuple|None): (sn, said) of the anchoring key event, or None
            when no seal in the KEL matches
    """
    kever = _kever(db, pre)
    if kever is None:
        return None
    for sn in range(kever.sn + 1):
        dig = db.kels.getLast(keys=pre, on=sn)
        if dig is None:
            continue
        eserder = db.evts.get(keys=(pre, dig))
        if eserder is None:
            continue
        if said in sealDigests(eserder):
            return (sn, eserder.said)
    return None


def _verifyAnchorCouple(serder, *, db, issuer, number, diger):
    """Verify one explicit local KEL anchor couple against a TEL event seal.

    Parameters:
        serder (SerderACDC): TEL event whose anchor couple to verify.
        db (Baser): local KEL database that stores the controlling habitat's
            verified key events.
        issuer (str): qb64 AID whose KEL must contain the sealing event.
        number (Number | None): claimed sequence number of the sealing KEL
            event.
        diger (Diger | None): claimed digest of the sealing KEL event.

    Returns:
        bool: True when the claimed sealing event exists, is fully witnessed,
            matches ``diger``, and contains the full TEL seal tuple for
            ``serder``. False otherwise.
    """

    # Return False if either is missing
    if number is None or diger is None:
        return False

    # Retrieve dig of KEL event by issuer and sequence number
    dig = db.kels.getLast(keys=issuer, on=number.sn)
    if dig is None:
        return False

    dig = dig.encode("utf-8")
    
    # Retrieve serder from evts
    aserder = db.evts.get(keys=(issuer, dig))
    if aserder is None:
        return False

    # The claimed SAID must match, and the key event must be fully witnessed
    if aserder.said != diger.qb64 or not db.fullyWitnessed(aserder):
        return False

    # Compare against the full TEL seal tuple used by the local issuer path,
    # not just the TEL event digest.
    event = _normalizeEventRecord(serder)

    # Build the seal tuple from the TEL event for comparison
    seal = dict(i=event.regk, s=event.serder.sad['n'], d=event.said)

    # Loop through the seals in serder and return True if any match the TEL event's seal
    for candidate in aserder.ked.get("a", []):
        if not isinstance(candidate, Mapping):
            continue
        if (candidate.get("i") == seal["i"] and
                candidate.get("s") == seal["s"] and
                candidate.get("d") == seal["d"]):
            return True

    return False


# Verifier-side public API
def vetAnchor(serder, *, db, issuer, source=None, told=()):
    """Verify that the registry (TEL) event serder is anchored in the
    issuer's KEL: some key event of the issuer carries a seal whose digest is
    the TEL event's SAID.

    Returns:
        couple (tuple): (sn, said) of the anchoring key event in the
            issuer's KEL

    Parameters:
        serder (SerderACDC): registry event whose anchor to verify
        db (Baser): KEL database the caller has already populated and
            verified.  KEL verification is not performed here.
        issuer (str): qb64 AID of the registry's issuer (the rip's i field).
            The anchoring KEL's controller must be this AID: a seal in any
            other KEL is an endorsement, not a commitment.
        source (int|str|None): optional caller's claim of where the anchor
            lives in the issuer's KEL, by key event sequence number (int) or
            SAID (str).  A claim that resolves to an event whose seal
            digests match no event of the presented TEL (per told) is an
            aggregate (Merkle/SMT root) seal and is refused by name.  A
            claim that does not pan out otherwise falls back to a full scan,
            since a wrong hint is indistinguishable from an anchor not yet
            gathered.
        told (Iterable[str]): SAIDs of all events of the presented TEL, used
            only to discriminate an aggregate seal from a merely mistaken
            source claim.

    Raises:
        MisanchorError: seal found, but only in a KEL whose controller is
            not the issuer (permanent refusal)
        RootSealError: the claimed anchoring event seals digests foreign to
            the whole presented TEL (permanent refusal)
        MissingAnchorError: no seal found anywhere; the anchor may still be
            in flight (retryable)
    """
    if _kever(db, issuer) is None:
        raise MissingAnchorError(f"Issuer KEL for {issuer} not available to "
                                 f"verify the anchor of registry event "
                                 f"{serder.said}.")

    if source is not None:
        eserder = _kelEvent(db, issuer, source)
        if eserder is not None:
            digs = sealDigests(eserder)
            if serder.said in digs:
                return (eserder.sn, eserder.said)
            if digs and not set(digs) & set(told):
                raise RootSealError(f"Claimed anchoring key event "
                                    f"{eserder.said} at sn={eserder.sn} of "
                                    f"issuer {issuer} seals digest(s) "
                                    f"matching no event of the presented "
                                    f"registry {list(told)[:1]}: an "
                                    f"aggregate (Merkle/SMT root) seal "
                                    f"requires an inclusion proof and is "
                                    f"not supported.")
        # a claim that did not pan out is just a bad hint: fall through

    couple = _scanKel(db, issuer, serder.said)
    if couple is not None:
        return couple

    for pre in list(db.kevers):
        if pre == issuer:
            continue
        if _scanKel(db, pre, serder.said) is not None:
            raise MisanchorError(f"Seal for registry event {serder.said} "
                                 f"found in the KEL of {pre}, which is not "
                                 f"the registry issuer {issuer}: an "
                                 f"endorsement is not a commitment.")

    raise MissingAnchorError(f"No anchoring seal for registry event "
                             f"{serder.said} in the KEL of issuer {issuer}.")


def vetRip(rip):
    """Validate a registry inception (rip) event's registry-level fields.
    Field presence, order, and SAID are already SerderACDC's own validation.

    Returns:
        serder (SerderACDC): the validated rip event
    """
    return _validateRip(rip).serder


def vetUpdate(bup, rip):
    """Validate a blindable registry update (bup) event's registry-level
    fields against its registry inception.

    Returns:
        serder (SerderACDC): the validated bup event
    """
    return _validateUpdate(bup, regid=vetRip(rip).said).serder


def vetBlind(blinder, *, blid):
    """Verify a disclosed blinded-state attribute block against the BLID
    anchored by a blindable update (bup) event, by recomputing the BLID over
    the disclosed fields.

    Returns:
        (acdc, state) (tuple[str, str]): the disclosed transaction ACDC said
            and transaction state string; both empty for a placeholder

    Parameters:
        blinder (Blinder|str|bytes): the disclosed block, either a Blinder
            instance or the qb64 concatenation of its CESR field values as a
            discloser attaches it on the wire
        blid (str): qb64 BLID, the b field of the bup event

    Raises:
        UnverifiedBlindError: the disclosure does not reproduce blid, so it
            proves nothing about the registry's state
    """
    candidates = []
    if isinstance(blinder, Blinder):
        candidates.append(blinder)
    else:
        qb64 = blinder.decode() if hasattr(blinder, "decode") else blinder
        for clan in (BlindState, BoundState):
            try:
                candidates.append(Blinder(clan=clan, qb64=qb64))
            except Exception:
                continue
        if not candidates:
            raise UnverifiedBlindError(f"Undecodable disclosed blinded-state "
                                       f"block for blid={blid}.")

    for candidate in candidates:
        crew = dict(candidate.crew._asdict())
        crew['d'] = ''
        redone = Blinder(crew=candidate.clan(**crew), makify=True)
        if redone.said == blid:
            return (redone.acdc, redone.state)

    raise UnverifiedBlindError(f"Disclosed blinded-state block does not "
                               f"reproduce the anchored blid={blid}: the "
                               f"disclosure proves nothing.")


def vetBindings(acdc, *, regid, td):
    """Verify the binding equalities between a presented ACDC and its
    registry evidence.  These two equalities are the issuer's only
    commitment to the credential: v2 ACDCs are not directly signed, so a
    verifier that skips them passes every other obligation while accepting a
    substituted credential.

    Returns:
        binding (str): 'mutual' when td == acdc.d and acdc.rd == rip.d both
            hold; 'oneway' when the ACDC carries no rd, so only the
            registry->ACDC direction is committed and the caller's policy
            can weigh the weaker basis

    Parameters:
        acdc (SerderACDC|bytes): the presented ACDC
        regid (str): qb64 SAID of the presented registry inception (rip)
        td (str|None): qb64 transaction ACDC said the registry's verified
            head state commits to

    Raises:
        MisbindingError: either equality fails (permanent refusal)
    """
    serder = _coerce(acdc)
    if td != serder.said:
        raise MisbindingError(f"Registry state's transaction ACDC said "
                              f"td={td} does not bind the presented ACDC's "
                              f"said {serder.said}.")
    rd = serder.sad.get('rd')
    if rd:
        if rd != regid:
            raise MisbindingError(f"Presented ACDC's registry said rd={rd} "
                                  f"does not bind the presented registry "
                                  f"inception's said {regid}.")
        return 'mutual'
    return 'oneway'


def vet(rip, updates=None, *, db, acdc=None, blinder=None, sources=None):
    """Verify a registry (TEL) event chain against the issuer's KEL and
    determine the registry's verified state.  This is the party-side
    verification core: it fetches nothing and concludes only from the
    supplied evidence.

    The registry's state is the state at the highest-n event that
    chain-verifies from the rip and whose anchor verifies in the issuer's
    KEL.  Every presented event must anchor-verify: an event whose anchor is
    missing establishes nothing and the whole determination is retryable
    (MissingAnchorError), since concluding from an anchored prefix could
    silently bless an issuer's half-commitment or hide duplicity still in
    flight.

    Returns:
        record (RegStateRecord): the verified registry state

    Parameters:
        rip (SerderACDC|bytes): registry inception event
        updates (Iterable|None): registry update (bup) events, in any order
        db (Baser): KEL database the caller has already populated; KEL
            verification is the caller's job
        acdc (SerderACDC|bytes|None): optionally, the presented ACDC to
            bind-check against the verified head state
        blinder (Blinder|str|bytes|None): optionally, the disclosed
            blinded-state block for the head bup event.  Without it a bup
            head verifies as a chain but its state stays blinded (state and
            acdc None in the record).  There is no salt parameter: only the
            per-event disclosure is accepted.
        sources (Mapping|None): optional caller's claims of anchor
            locations, mapping TEL event said -> issuer KEL event sn (int)
            or said (str).  See vetAnchor.

    Raises:
        MissequenceError, MisdigestError, MisregistryError,
        MisanchorError, RootSealError, DuplicitousRegistryError,
        MisbindingError, UnverifiedBlindError: permanent, named refusals
        MissingAnchorError: establishes nothing, retryably
    """
    ripper = vetRip(rip)
    issuer = ripper.sad['i']
    updates = [vetUpdate(update, ripper)
               for update in (updates if updates is not None else ())]
    sources = sources if sources is not None else {}
    told = [ripper.said] + [serder.said for serder in updates]

    chain = [ripper]
    anchors = [vetAnchor(ripper, db=db, issuer=issuer,
                         source=sources.get(ripper.said), told=told)]

    remaining = list(updates)
    prior = ripper
    n = 1
    while remaining:
        cands = [serder for serder in remaining
                 if Number(numh=serder.sad['n']).num == n]
        if not cands:
            ns = sorted(Number(numh=serder.sad['n']).num
                        for serder in remaining)
            raise MissequenceError(f"Gapped chain for registry "
                                   f"{ripper.said}: no event at n={n} but "
                                   f"events remain at n={ns}; n = prior + 1 "
                                   f"exactly.")
        for serder in cands:
            if serder.sad['p'] != prior.said:
                raise MisdigestError(f"Registry event {serder.said} at "
                                     f"n={n} has p={serder.sad['p']} which "
                                     f"is not the prior event's said "
                                     f"{prior.said}.")
        unique = list({serder.said: serder for serder in cands}.values())
        couples = {}
        for serder in unique:  # every event must anchor before any concludes
            couples[serder.said] = vetAnchor(serder, db=db, issuer=issuer,
                                             source=sources.get(serder.said),
                                             told=told)
        if len(unique) > 1:
            raise DuplicitousRegistryError(f"Registry duplicity for "
                                           f"{ripper.said}: {len(unique)} "
                                           f"distinct anchored events at "
                                           f"n={n}: "
                                           f"{[s.said for s in unique]}.")
        accepted = unique[0]
        chain.append(accepted)
        anchors.append(couples[accepted.said])
        remaining = [serder for serder in remaining
                     if Number(numh=serder.sad['n']).num != n]
        prior = accepted
        n += 1

    head = chain[-1]
    acdcsaid = state = None
    if head.ilk == Ilks.bup and blinder is not None:
        disclosed, toldState = vetBlind(blinder=blinder, blid=head.sad['b'])
        acdcsaid = disclosed or None
        state = toldState or None

    binding = None
    if acdc is not None:
        serder = _coerce(acdc)
        if head.ilk == Ilks.bup and blinder is None:
            raise UnverifiedBlindError(f"Registry {ripper.said} head at "
                                       f"n={head.sad['n']} is blinded and "
                                       f"no state was disclosed: nothing "
                                       f"binds ACDC {serder.said} to it.")
        binding = vetBindings(acdc=serder, regid=ripper.said, td=acdcsaid)

    return RegStateRecord(regid=ripper.said, issuer=issuer, said=head.said,
                          sn=Number(numh=head.sad['n']).num, ilk=head.ilk,
                          acdc=acdcsaid, state=state, stamp=head.sad['dt'],
                          binding=binding, anchors=tuple(anchors))


# Issuer-side local TEL engine
class _RegEventer:
    """Private issuer-side TEL event engine for one local registry.

    It owns the local TEL workflow that ``Registry`` delegates to:
    shared TEL validation, local KEL anchor discovery and verification,
    acceptance into the ordered registry log, and replay of missing-anchor
    and out-of-order escrows.
    """

    def __init__(self, hab, store, regk=None, regd=None):
        """Create one local TEL event engine bound to a habitat and store.

        Parameters:
            hab (Hab): controlling habitat whose KEL anchors registry events.
            store (RegistryStore): storage adapter for TEL events, accepted
                ordering, anchors, and escrows.
            regk (str | None): bound registry identifier when reopening or
                attaching to an existing local registry state.
            regd (str | None): accepted head-event SAID when already known.
        """
        # The engine needs the controlling habitat for local KEL inspection,
        # the registry store for persistence, and the current accepted TEL tip
        self.hab = hab
        self.store = store
        self.regk = regk
        self.regd = regd
    
    
    @property
    def head(self):
        """Return the accepted head SAID for the bound local registry.

        Returns:
            Saider | None: current accepted head SAID, or None when the
                registry has not yet committed any event.
        """
        return self.store.head(self.regk) if self.regk is not None else None

    @property
    def sn(self):
        """Return the accepted head sequence number for the bound registry.

        Returns:
            int: accepted head sequence number, or ``-1`` when no TEL event
                has been committed yet.
        """
        head = self.store.headEvent(self.regk) if self.regk is not None else None
        return _normalizeEventRecord(head).sn if head is not None else -1

    @property
    def regser(self):
        """Return the accepted registry inception event when available.

        Returns:
            SerderACDC | None: committed ``rip`` event, or None when the
                registry inception has not yet been accepted.
        """
        return self.store.seqEvent(self.regk, 0) if self.regk is not None else None

    # Public TEL event API
    def processEvent(self, serder):
        """Store one TEL event and commit it when anchor and order allow.

        Parameters:
            serder (SerderACDC): candidate local registry event to process.

        Returns:
            bool: True when the event commits immediately or replays
                idempotently as already accepted. False when the event is
                staged in missing-anchor or out-of-order escrow.

        Raises:
            ValidationError: if the event fails shared TEL validation or
                conflicts with accepted local registry state.
        """
        # First apply shared TEL rules plus local store consistency checks.
        event, existing, prior = self._validateEvent(serder)

        # The first accepted or staged rip binds this engine instance to the
        # registry key it will manage from then on.
        if self.regk is None and event.ilk == Ilks.rip:
            self.regk = event.regk
            self.regd = event.said

        # Idempotent replay of an already accepted event is a success.
        if existing is not None:
            self.regk = event.regk
            self.regd = existing.said
            return True

        # Persist the body before any escrow decision so later replay can load
        # the full event again.
        self.store.putEvent(event.serder)

        # Try a single local KEL discovery pass before deciding whether the
        # event must wait in missing-anchor escrow.
        self._discoverAnchor(event)
        if self.store.anchor(event.said) is None:
            self.store.escrowMissingAnchor(event.regk, event.sn, event.said)
            return False

        # Once an anchor exists, remove any stale maes entry for this event.
        self.store.baser.maes.rem(keys=event.regk, on=event.sn, val=event.said)

        # A rip only depends on its own verified anchor.
        if event.ilk == Ilks.rip:
            self._commit(event)
            self._processQueued()
            return True

        # Updates with a verified anchor but no accepted predecessor move to
        # out-of-order escrow until the chain gap is filled.
        if prior is None:
            self.store.escrowOutOfOrder(event.regk, event.sn, event.said)
            return False

        # Anchored and properly ordered updates can commit immediately.
        self._commit(event)
        self._processQueued()
        return True

    def anchorMsg(self, said, number=None, diger=None):
        """Validate and record the local KEL anchor for one stored TEL event.

        Parameters:
            said (str): SAID of the stored TEL event to anchor.
            number (Number | None): optional sequence number of the sealing
                KEL event. Must be supplied together with ``diger``.
            diger (Diger | None): optional digest of the sealing KEL event.
                Must be supplied together with ``number``.

        Returns:
            bool: True when anchoring lets the event commit immediately or it
                was already accepted, False when the event remains queued
                behind a missing predecessor.

        Raises:
            ValidationError: if the stored TEL event is unknown, if only one of
                ``number`` or ``diger`` is supplied, or if the explicit or
                discovered local anchor does not verify.
        """
        # Explicit anchoring always starts from the already stored TEL body.
        serder = self.store.event(said)
        if serder is None:
            raise ValidationError(f"unknown registry event {said}")

        # Reuse the normal validation gate so bad stored bodies do not leave
        # anchors behind.
        event, _, _ = self._validateEvent(serder)
        if (number is None) != (diger is None):
            raise ValidationError("anchorMsg requires both number and diger or neither")

        if number is None or diger is None:
            # With no explicit couple, fall back to the same local KEL discovery
            # path used by normal event ingestion and escrow replay.
            self._discoverAnchor(event)
        elif not _verifyAnchorCouple(event.serder,
                                     db=self.hab.db,
                                     issuer=self.hab.pre,
                                     number=number,
                                     diger=diger):
            raise ValidationError(f"invalid anchor for registry event {said}")
        else:
            # Store the verified explicit couple so the normal state machine can
            # continue from the exact same persisted anchor representation.
            self.store.putAnchor(said, number, diger)

        if self.store.anchor(said) is None:
            raise ValidationError(f"invalid anchor for registry event {said}")

        # Hand back to the main event path so commit vs ooes behavior stays
        # centralized in one place.
        return self.processEvent(event.serder)

    def processEscrows(self):
        """Retry missing-anchor and out-of-order escrows for this registry.

        Parameters:
            None

        Returns:
            None
        """
        self._processMissingAnchors()
        self._processQueued()

    def blind(self, acdc, state, **kwa):
        """Create and stage one blindable registry state update event.

        Parameters:
            acdc (SerderACDC): transaction-state ACDC that must already belong
                to this registry and be issued by this habitat.
            state (str): logical state value committed by the new blinded TEL
                update.
            **kwa: keyword arguments forwarded to ``Blinder.blind`` and
                ``messaging.blindate``. Blinder-construction keys are removed
                before the TEL event body is created.

        Returns:
            tuple: ``(blinder, serder)`` where ``blinder`` is the derived
                ``Blinder`` and ``serder`` is the staged ``bup`` event.

        Raises:
            ConfigurationError: if the registry has no accepted anchored
                frontier yet, if ``acdc`` is invalid, if it does not belong to
                this registry or issuer, or if a caller-supplied ``blinder``
                override is provided.
        """
        # Build the next bup off the effective staged frontier, not just the
        # last committed head, so pipelined local issuance chains correctly.
        tip = self._effectiveFrontier()
        if tip is None:
            raise ConfigurationError("registry must be anchored before updates")

        # The issuer-side blind path only accepts a full, self-verifying ACDC.
        if not isinstance(acdc, SerderACDC):
            raise ConfigurationError("acdc must be a SerderACDC")
        if not acdc.verify():
            raise ConfigurationError(f"acdc {acdc.said} is invalid")

        # The ACDC must already declare this registry as its governing TEL.
        regid = getattr(acdc, "regid", None)
        if regid is None:
            regid = acdc.sad.get("rd")
        if regid != self.regk:
            raise ConfigurationError(f"acdc {acdc.said} does not belong to registry {self.regk}")

        # The current habitat must also be the ACDC's issuer.
        issuer = getattr(acdc, "israid", None)
        if issuer is None:
            issuer = acdc.sad.get("i")
        if issuer != self.hab.pre:
            raise ConfigurationError(f"acdc {acdc.said} has issuer {issuer} not {self.hab.pre}")
        if "blinder" in kwa:
            raise ConfigurationError("caller-supplied blinder overrides are not supported")

        blindkwa = {}
        for key in ("raw", "salt", "tier", "bound", "bsn", "bd"):
            if key in kwa:
                # These options belong to blinder construction, not the TEL
                # event body, so peel them off before calling blindate().
                blindkwa[key] = kwa.pop(key)

        tipEvent = _normalizeEventRecord(tip)
        sn = tipEvent.sn + 1
        # Derive the blinder from the next TEL sequence number so the bup and
        # blinded state commit to the same step in the chain.
        blinder = Blinder.blind(sn=sn, acdc=acdc.said, state=state, **blindkwa)
        serder = messaging.blindate(regid=self.regk,
                                    prior=tipEvent.said,
                                    blid=blinder.said,
                                    sn=sn,
                                    **kwa)
        self.processEvent(serder)
        return blinder, serder

    # Shared local validation and acceptance helpers
    def _validateEvent(self, serder):
        """Validate one TEL event against shared TEL rules and local state.

        Parameters:
            serder (SerderACDC): candidate TEL event to validate for local
                issuer-side processing.

        Returns:
            tuple: ``(event, existing, prior)`` where ``event`` is the
                normalized ``_RegEventRecord``, ``existing`` is the already
                accepted event at the same slot when present, and ``prior`` is
                the accepted predecessor event for updates when already known.

        Raises:
            ValidationError: if the event does not belong to this registry, if
                the first local event is not a ``rip``, if the issuer is
                invalid, or if a different event already occupies the accepted
                ``(regk, sn)`` slot.
            MisregistryError, MissequenceError, MisdigestError: if shared TEL
                validation fails for registry id, sequence number, or prior
                linkage.
        """

        # Before a registry is bound, first event must be a rip
        if self.regk is None:
            if serder.ilk != Ilks.rip:
                raise ValidationError("registry must start with an inception event")

            # Validate the rip against the local habitat's AID
            event = _validateRip(serder, issuer=self.hab.pre)
        else:
            # Once bound, reuse the shared TEL validators against the already
            # known registry id and local habitat issuer.
            event = _validateRip(serder, issuer=self.hab.pre) if serder.ilk == Ilks.rip \
                else _validateUpdate(serder, regid=self.regk)

        # Validate that the event belongs to the same registry
        if self.regk is not None and event.regk != self.regk:
            raise ValidationError(f"registry event {event.said} does not belong "
                                  f"to {self.regk}")

        # Validate that the event's sequence number is not already accepted with a different SAID
        existing = self.store.seqEvent(event.regk, event.sn)
        if existing is not None and existing.said != event.said:
            raise ValidationError(f"conflicting registry event at "
                                  f"{event.regk}:{event.sn}")

        prior = None
        if event.ilk != Ilks.rip:
            # If the predecessor is already accepted locally, make the update's
            # p field prove it before we stage or replay anything.
            prior = self.store.seqEvent(event.regk, event.sn - 1)

            if prior is not None:
                _validateUpdate(event.serder, regid=event.regk, prior=prior.said)

        return event, existing, prior

    def _commit(self, event):
        """Accept one verified TEL event into the ordered local registry log.

        Parameters:
            event (_RegEventRecord): normalized TEL event already verified for
                registry membership, anchor presence, and ordering.

        Returns:
            SerderACDC: committed TEL event serder.
        """

        # Persist the winner into the ordered TEL and then clear all escrow
        # entries for that exact slot because the slot is now decided.
        self.store.accept(event.regk, event.sn, event.serder)
        for escrowdb in (self.store.baser.maes, self.store.baser.ooes):
            for (said,) in escrowdb.get(keys=event.regk, on=event.sn):
                escrowdb.rem(keys=event.regk, on=event.sn, val=said)

        # Update the registry key and digest
        self.regk = event.regk
        self.regd = event.said

        return event.serder

    def _discoverAnchor(self, event):
        """Find and persist the first verified local KEL seal for one TEL event.

        Parameters:
            event (_RegEventRecord): normalized TEL event whose local KEL
                anchor to discover.

        Returns:
            bool: True when an anchor is already stored or a newly discovered
                local KEL seal verifies and is persisted. False when no usable
                local sealing event is visible yet.
        """
        
        # Check if the anchor is already known and stored
        if self.store.anchor(event.said) is not None:
            return True

        # Ask the local habitat KEL for the latest key event whose seal payload
        # points at this TEL event.
        aserder = self.hab.db.fetchLastSealingEventByEventSeal(
            pre=self.hab.pre,
            seal=dict(i=event.regk, s=event.serder.sad['n'], d=event.said),
        )
        if aserder is None:
            return False

        # Retrieve the sn and and dig from the sealing event and verify the anchor couple
        number = Number(num=aserder.sn)
        diger = Diger(qb64=aserder.said)
        if not _verifyAnchorCouple(event.serder,
                                   db=self.hab.db,
                                   issuer=self.hab.pre,
                                   number=number,
                                   diger=diger):
            return False

        self.store.putAnchor(event.said, number, diger)
        return True

    # Escrow replay helpers
    def _anchorWinnerKey(self, said):
        """Return the deterministic sibling winner key for one staged event.

        Parameters:
            said (str): SAID of the staged TEL event being ordered.

        Returns:
            tuple: sibling arbitration key ordered by earliest verified anchor,
                then diger, then event SAID.
        """
        anchor = self.store.anchor(said)
        if anchor is None:
            return float("inf"), "", said
        number, diger = anchor
        return number.sn, diger.qb64, said

    def _replayCandidate(self, said, sn):
        """Load and revalidate one escrowed TEL event for replay.

        Parameters:
            said (str): SAID of the escrowed TEL event.
            sn (int): escrow slot sequence number used to clear stale entries.

        Returns:
            tuple | None: ``(event, prior)`` for a replayable staged TEL event,
                or None when the escrow entry is unrecoverable and has been
                pruned.
        """
        serder = self.store.event(said)
        if serder is None:
            # A dangling escrow entry with no body cannot recover.
            self.store.clearEscrows(self.regk, sn, said)
            return None

        try:
            # Re-validate on replay so malformed staged data is pruned instead
            # of being retried forever.
            event, existing, prior = self._validateEvent(serder)
        except ValidationError:
            self.store.clearEscrows(self.regk, sn, said)
            return None

        if existing is not None and existing.said != said:
            # A different sibling has already claimed the accepted slot.
            self.store.clearEscrows(self.regk, sn, said)
            return None

        return event, prior

    def _processMissingAnchors(self):
        """Retry missing-anchor escrows using newly visible local KEL seals.

        Parameters:
            None

        Returns:
            None
        """
        if self.regk is None:
            return

        # Re-group by TEL sequence number so sibling candidates compete as a
        # set instead of in database iteration order.
        escrowed = {}
        for _, sn, said in self.store.baser.maes.getTopItemIter(keys=self.regk):
            escrowed.setdefault(sn, []).append(said)

        for sn in sorted(escrowed):
            candidates = []
            for said in escrowed[sn]:
                replay = self._replayCandidate(said, sn)
                if replay is None:
                    continue

                event, _ = replay
                # Replay is what lets a now-visible KEL seal move an event from
                # "missing anchor" toward acceptance.
                self._discoverAnchor(event)
                candidates.append(event.serder)

            # Order competing siblings by their earliest verified anchor so the
            # same event wins regardless of raw database iteration order.
            for serder in sorted(candidates, key=lambda serder: self._anchorWinnerKey(serder.said)):
                try:
                    # Re-enter the normal state machine so the candidate either
                    # commits, moves to ooes, or remains staged in maes.
                    self.processEvent(serder)
                except ValidationError:
                    self.store.clearEscrows(self.regk, sn, serder.said)

    def _processQueued(self):
        """Advance out-of-order escrows whose predecessors now exist locally.

        Parameters:
            None

        Returns:
            None
        """
        if self.regk is None:
            return

        while True:
            # Only the next sequence number after the accepted head can advance.
            sn = self.sn + 1
            queued = [said for (said,) in self.store.baser.ooes.get(keys=self.regk, on=sn)]
            if not queued:
                return

            advanced = False
            # Use the same sibling winner policy here as missing-anchor replay
            # so queued and missing-anchor escrows resolve races identically.
            for said in sorted(queued, key=self._anchorWinnerKey):
                replay = self._replayCandidate(said, sn)
                if replay is None:
                    continue

                event, prior = replay
                # ooes only advances events whose anchors are already known.
                if self.store.anchor(said) is None:
                    continue

                # If the immediate predecessor still is not accepted, the event
                # remains queued for a later pass.
                if prior is None:
                    continue

                # Commit one event per pass, then loop so the next sequence slot
                # sees the updated accepted head.
                self._commit(event)
                advanced = True
                break

            if not advanced:
                return

    # Issuance helper
    def _effectiveFrontier(self):
        """Return the effective TEL frontier, including one staged successor chain.

        Returns:
            SerderACDC | None: accepted head event extended by a single
                unambiguous staged successor chain, or None when no accepted
                head exists yet.

        Raises:
            ConfigurationError: if multiple staged successors compete for the
                same next TEL sequence number.
        """
        
        # Start from the accepted TEL head and then walk forward through any
        # single unambiguous staged successor chain.
        tip = self.store.headEvent(self.regk) if self.regk is not None else None
        while tip is not None:
            tipEvent = _normalizeEventRecord(tip)
            sn = tipEvent.sn + 1
            saids = []
            seen = set()
            for escrowdb in (self.store.baser.maes, self.store.baser.ooes):
                for (said,) in escrowdb.get(keys=self.regk, on=sn):
                    # The same event may be observed across escrows during
                    # replay-heavy flows, so de-duplicate by SAID.
                    if said not in seen:
                        seen.add(said)
                        saids.append(said)

            matches = []
            for said in saids:
                staged = self.store.event(said)
                if staged is None:
                    continue
                stagedEvent = _normalizeEventRecord(staged)
                # Only events that point at the current frontier are eligible
                # to extend it for pipelined issuance.
                if stagedEvent.prior == tipEvent.said:
                    matches.append(stagedEvent)

            if not matches:
                break
            # Multiple staged successors at one slot mean the local staged TEL
            # has forked, so issuance fails closed instead of guessing.
            if len(matches) > 1:
                raise ConfigurationError(f"registry {self.regk} has conflicting staged successors at sn {sn}")
            tip = matches[0].serder

        return tip
