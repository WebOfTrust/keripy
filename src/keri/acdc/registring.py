# -*- encoding: utf-8 -*-
"""
keri.acdc.registring module

Registry (TEL) event support

Party-side verification core for ACDC v2 blindable state registries (TELs)
made of 'rip' (registry inception) and 'bup' (blindable update) events.  Given
a supplied registry event chain, the issuer's KEL evidence, and optionally a
disclosed blinded-state block, vet() and the vet* helpers determine the
registry's verified state.  The core fetches nothing and concludes only from
the evidence handed to it; KEL verification remains the caller's job.

This complements keri.acdc.registraring, which manages the registries a local
habitat controls.  Where that module issues, this one judges: its evidence is
another party's, its anchor search runs against that party's KEL, and its
refusals are named so a caller can tell a permanent one from a retryable one.
"""

from collections.abc import Mapping
from collections import namedtuple

from .. import help
from ..kering import (Ilks, ValidationError, InvalidValueError,
                      MissingAnchorError, MisdigestError, MissequenceError,
                      MisregistryError, MisanchorError, RootSealError,
                      MisbindingError, DuplicitousRegistryError,
                      UnverifiedBlindError)
from ..core import Blinder, BlindState, BoundState, Number, SerderACDC

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


def _kever(db, pre):
    """Return the Kever for pre from db's read-through kevers cache, or None
    when the KEL is not available."""
    try:
        return db.kevers[pre]
    except KeyError:
        return None


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


def _kelEvent(db, pre, claim):
    """Resolve a claimed anchoring key event of pre's KEL by sequence number
    (int) or SAID (str).  Returns the event serder or None when absent."""
    if isinstance(claim, int):
        dig = db.kels.getLast(keys=pre, on=claim)
        if dig is None:
            return None
        return db.evts.get(keys=(pre, dig))
    return db.evts.get(keys=(pre, claim))


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
    serder = _coerce(rip)
    if serder.ilk != Ilks.rip:
        raise ValidationError(f"Expected registry inception ilk={Ilks.rip} "
                              f"got ilk={serder.ilk} for event "
                              f"{serder.said}.")
    if Number(numh=serder.sad['n']).num != 0:
        raise MissequenceError(f"Registry inception {serder.said} has "
                               f"n={serder.sad['n']} but inception must be "
                               f"at n=0.")
    return serder


def vetUpdate(bup, rip):
    """Validate a blindable registry update (bup) event's registry-level
    fields against its registry inception.

    Returns:
        serder (SerderACDC): the validated bup event
    """
    serder = _coerce(bup)
    if serder.ilk != Ilks.bup:
        raise ValidationError(f"Expected registry update ilk={Ilks.bup} got "
                              f"ilk={serder.ilk} for event {serder.said}.")
    if serder.sad['rd'] != rip.said:
        raise MisregistryError(f"Registry update {serder.said} has "
                               f"rd={serder.sad['rd']} which is not the "
                               f"presented registry inception's said "
                               f"{rip.said}.")
    if Number(numh=serder.sad['n']).num < 1:
        raise MissequenceError(f"Registry update {serder.said} has "
                               f"n={serder.sad['n']} but updates must be at "
                               f"n >= 1.")
    return serder


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
