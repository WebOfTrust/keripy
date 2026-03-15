# -*- encoding: utf-8 -*-
"""
kraming module - KRAM (KERI Request Authentication Mechanism) implementation

This module implements Full KRAM, a monotonic timed cache for preventing replay
attacks in KERI. The last request from any client is cached inside a sliding
time window. A new request must both have a later datetime than the cached
request and must be inside the host time window.

Full KRAM employs a strictly monotonically ordered timeliness cache to protect
from replay attacks. It includes protection from retrograde attacks on the
recipient's clock.
"""
from collections import namedtuple
from dataclasses import dataclass, astuple

from ordered_set import OrderedSet as oset

from .. import help, kering
from ..core import Verser, coring, eventing, indexing
from ..help import helping
from ..recording import CacheTypeRecord, MsgCacheRecord, TxnMsgCacheRecord

logger = help.ogler.getLogger()


@dataclass(frozen=True)
class AuthTypeCodex:
    """AuthTypeCodex is codex of KRAM authentication type code strings.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    AttachedSealReference: str = 'asr'  # Attached seal reference. Short lag window.
    AttachedSignatureSingleKey: str = 'assk'  # Attached single-key signature. Short lag window.
    AttachedSignatureMultiKey: str = 'asmk'  # Attached multi-key signature. Long lag window. Accumulates sigs.

    def __iter__(self):
        return iter(astuple(self))

AuthTypes = AuthTypeCodex()

SigVerifyResult = namedtuple("SigVerifyResult", "verified sigers")
"""Result of _verifyAttachedSigs dispatching.

Fields:
    verified (bool): True if at least one signature verified
    sigers (list[Siger]): verified Siger instances (empty for cigars)

Key state ref and tholder are derivable from the sender's kever
(current key state) and are not included here. Callers that need
them should construct directly from kever.sner, kever.serder.said,
and kever.tholder.
"""


class Kramer:
    def __init__(self, db, cf=None, cues=None):
        self.db = db
        self.cf = cf if cf else None

        # Define cues
        self.cues = cues if cues is not None else []

        # Load config once at init, inject into runtime state
        config = self.cf.get()
        kram = config.get('kram', {})

        self._enabled = kram.get('enabled', False)

        self._fullDenials = kram.get('denials', [])
        self._denials = self._compactDenials(self._fullDenials)

        self._ctypCf = kram.get('caches', {})
        self._populateCtyp(self._ctypCf)

    def _populateCtyp(self, ctypCf):
        """Prepopulate ctyp cache with configured values.

        Validates each cache-type tuple against KRAM spec constraints before pinning.
        Raises KramConfigurationError if any constraint is violated.

        Parameters:
            ctypCf (dict): cache-type config key -> list of (d, sl, ll, xl, psl, pll, pxl)
        """
        for key, val in ctypCf.items():
            try:
                record = CacheTypeRecord(*map(int, val))
            except Exception as e:
                raise kering.KramConfigurationError(
                    f"Invalid cache configuration for {key}, {val}: {e}")

            if record.d < 0:
                raise kering.KramConfigurationError(
                    f"Cache type {key}: d must be >= 0, got {record.d}")
            if not (record.sl > 0 and record.sl <= record.ll <= record.xl):
                raise kering.KramConfigurationError(
                    f"Cache type {key}: require 0 < sl <= ll <= xl, "
                    f"got sl={record.sl} ll={record.ll} xl={record.xl}")
            if record.psl < record.sl:
                raise kering.KramConfigurationError(
                    f"Cache type {key}: psl must be >= sl, got psl={record.psl} sl={record.sl}")
            if record.pll < record.ll:
                raise kering.KramConfigurationError(
                    f"Cache type {key}: pll must be >= ll, got pll={record.pll} ll={record.ll}")
            if record.pxl < record.xl:
                raise kering.KramConfigurationError(
                    f"Cache type {key}: pxl must be >= xl, got pxl={record.pxl} xl={record.xl}")

            self.db.ctyp.pin(key, record)

    @staticmethod
    def _compactDenials(fullDenials):
        """Compact raw denials into strings of the form Mmm.iii.route

        Where:
            Mmm = three-character base64 version from Verser.verToB64
            iii = three-character ilk (message type), may be empty
            route = route string, may be empty

        A trailing period is kept when route is absent to distinguish
        partial denials (version-only or version+ilk) from full ones.

        Parameters:
            fullDenials (list): raw denials [[major, minor], ilk, route]

        Returns:
            list: compact denial strings
        """
        compact = []
        for denial in fullDenials:
            try:
                vrsn, ilk, route = denial
                major, minor = vrsn
                verB64 = Verser.verToB64(major=major, minor=minor)
                parts = [verB64]
                if ilk:
                    parts.append(ilk)
                if route:
                    parts.append(route)
                compact.append(".".join(parts) + ("" if route else "."))
            except Exception as e:
                raise kering.KramConfigurationError(f"Invalid denial for {denial}: {e}")
        return compact

    @property
    def enabled(self):
        return self._enabled

    @property
    def fullDenials(self):
        """Returns raw denials list from config.
        Each denial is [[major, minor], ilk, route]
        """
        return self._fullDenials

    @property
    def denials(self):
        """Returns compacted denials as strings of the form Mmm.iii.route"""
        return self._denials

    @staticmethod
    def denial(serder):
        """Returns compacted denial string for serder.

        Parameters:
            serder (SerderKERI): message instance
        """
        return f"{Verser.verToB64(version=serder.pvrsn)}.{serder.ilk}.{serder.route}"


    def _fetchCacheType(self, msgType, route):
        """Fetch the most specific matching cache-type entry.

        Uses Komer.getItemIter to scan the message-type branch of the ctyp
        database in a single LMDB cursor pass. The cursor positions at the
        first key >= msgType and iterates forward through all keys sharing
        the msgType prefix. Among matches, the most specific key (longest
        match against the message vector) is selected.

        Cascade specificity:
            1. msgType.R.route  (type + route, most specific)
            2. msgType          (type only)
            3. ~                (default catchall, separate lookup)

        Parameters:
            msgType (str): message ilk (qry, rpy, exn, etc.)
            route (str): message route string

        Returns:
            CacheTypeRecord: matching cache-type record

        Raises:
            KramError: if no matching cache-type entry found
        """
        bestRec = None
        exactRoute = f"{msgType}.R.{route}" if route else None

        # Single cursor scan of the msgType branch
        for keys, rec in self.db.ctyp.getItemIter(keys=msgType):
            key = self.db.ctyp.sep.join(keys)  # rejoin tuple to string
            if exactRoute and key == exactRoute:
                return rec  # exact type+route match, most specific
            elif key == msgType:
                bestRec = rec  # type-only match, keep as candidate

        if bestRec is not None:
            return bestRec

        # Fall back to default catchall
        rec = self.db.ctyp.get("~")
        if rec is not None:
            return rec

        raise kering.KramError(f"No cache-type entry found for "
                               f"msgType={msgType}, route={route}")


    @staticmethod
    def _hasSeals(senderId, **kwa):
        """Check if kwa contains seal reference attachments from the sender.

        Two attachment types qualify for KRAM seal-based authentication:

        sscs (seal source couples) are (number, diger) tuples that
        implicitly reference the sender's own KEL. Always qualify.

        ssts (seal source triples) are (prefixer, number, diger) tuples
        where the prefixer can point to any entity's KEL. Only qualify
        when prefixer.qb64 == senderId (i.e., the sender is sealing
        in their own KEL). Non-matching ssts are not dropped, they
        remain in kwa for downstream forwarding (e.g., ACDC credential
        anchoring) but do not contribute to KRAM authentication.

        tdcs (typed digest seal couples) contain protocol/version info
        and a digest but lack the event reference components (prefix,
        sequence number) needed to locate a specific event in the
        sender's KEL. Do not qualify.

        Parameters:
            senderId (str): sender AID prefix (qb64)
            **kwa: keyword arguments from parser exts dict

        Returns:
            bool: True if KRAM-applicable seal reference attachments present
        """
        if kwa.get('sscs'):
            return True
        for prefixer, number, diger in kwa.get('ssts', []):
            if prefixer.qb64 == senderId:
                return True
        return False


    @staticmethod
    def _hasSigs(senderId, **kwa):
        """Check if kwa contains signature attachments applicable to sender.

        Bare sigers always count. For cigars, ssgs, and tsgs, only entries
        matching senderId are considered. No keystate check is performed
        here since the kever is not yet available at the call site.

        Parameters:
            senderId (str): qb64 of sender AID
            **kwa: keyword arguments from parser exts dict

        Returns:
            bool: True if applicable signature attachments present
        """
        if kwa.get('sigers'):
            return True
        for cigar in kwa.get('cigars', []):
            if cigar.verfer.qb64 == senderId:
                return True
        for prefixer, sigers in kwa.get('ssgs', []):
            if prefixer.qb64 == senderId:
                return True
        for prefixer, number, sdiger, sigers in kwa.get('tsgs', []):
            if prefixer.qb64 == senderId:
                return True
        return False


    def _resolveAuthType(self, msg, kwa, kever, hasSealRef, hasSigs, senderId):
        """Resolve authentication type, validating seal exactly once for
        "both attached" case.

        For the "both attached" case (seal refs AND signatures present),
        seal validation is attempted here as part of type resolution
        (cheaper than sig verification). If valid, auth type resolves to
        AttachedSealReference with sealValidated=True so the caller skips
        re-validation. If invalid, falls back to signature auth type
        based on key list cardinality.

        Parameters:
            msg (SerderKERI): message being authenticated
            kwa (dict): keyword arguments from parser exts dict
            kever (Kever): sender's Kever instance
            hasSealRef (bool): True if seal reference attachments present
            hasSigs (bool): True if signature attachments present
            senderId (str): sender AID prefix (qb64)

        Returns:
            tuple: (authType, sealValidated) where authType is an
                AuthTypeCodex value (or None) and sealValidated is True
                if the seal was already validated during resolution
        """
        if hasSealRef and not hasSigs:
            return AuthTypes.AttachedSealReference, False

        if hasSigs and not hasSealRef:
            if len(kever.verfers) == 1:
                return AuthTypes.AttachedSignatureSingleKey, False
            return AuthTypes.AttachedSignatureMultiKey, False

        if hasSealRef and hasSigs:
            try:
                sealValid = self._validateSenderSeal(
                    msg, senderId, **kwa)
            except kering.MissingSenderKeyStateError:
                sealValid = False

            if sealValid:
                return AuthTypes.AttachedSealReference, True
            if len(kever.verfers) == 1:
                return AuthTypes.AttachedSignatureSingleKey, False
            return AuthTypes.AttachedSignatureMultiKey, False

        return None, False


    def _verifyAttachedSigs(self, *, msg, senderId, kever, **kwa):
        """Verify attached signatures using cigar gate then oset pooling.

        Cigars are tried first (either-or). If a cigar from the matching
        sender verifies, returns immediately. If no cigar verifies, builds
        an oset pool of sigers from all applicable sources (bare sigers,
        ssgs, tsgs) and verifies the pool in one pass against the sender's
        current key state.

        Gating logic for pool contributions:
            - bare sigers: always included
            - ssgs: prefixer must match senderId
            - tsgs: prefixer must match senderId AND (number, diger)
              must correspond to sender's current key state

        Signatures that fail crypto verification are dropped (not in the
        returned sigers). Signatures that don't apply (non-matching tsgs,
        non-sender ssgs) remain in kwa for downstream forwarding but are
        not counted toward KRAM threshold.

        Parameters:
            msg (SerderKERI): message being authenticated
            senderId (str): sender AID prefix (qb64)
            kever (Kever): sender's Kever instance (current key state)
            **kwa: keyword arguments from parser exts dict

        Returns:
            SigVerifyResult: namedtuple with (verified, sigers)
        """

        # If any cigar from the matching sender verifies, return immediately.
        for cigar in kwa.get('cigars', []):
            if cigar.verfer.transferable:
                continue  # skip transferable verfers
            if senderId != cigar.verfer.qb64:  # sender identity check
                continue
            if cigar.verfer.verify(cigar.raw, msg.raw):
                return SigVerifyResult(verified=True, sigers=[])

        # Build siger pool, oset by siger.qb64 to deduplicate.
        pool = oset()

        # Bare sigers, always included
        for siger in kwa.get('sigers', []):
            pool.add(siger.qb64)

        # ssgs gate: prefixer must match senderId
        for prefixer, sigers in kwa.get('ssgs', []):
            if prefixer.qb64 != senderId:
                continue
            for siger in sigers:
                pool.add(siger.qb64)

        # tsgs gate: prefixer matches AND current keystate matches
        for prefixer, number, sdiger, sigers in kwa.get('tsgs', []):
            if prefixer.qb64 != senderId:
                continue
            if (number.sn != kever.sner.num or
                    sdiger.qb64 != kever.serder.said):
                continue  # non-current keystate, passed on, not counted
            for siger in sigers:
                pool.add(siger.qb64)

        # Verify pool in one pass against current key state.
        if not pool:
            return SigVerifyResult(verified=False, sigers=[])

        poolSigers = [indexing.Siger(qb64=q) for q in pool]
        vsigers, _ = eventing.verifySigs(
            raw=msg.raw, sigers=poolSigers, verfers=kever.verfers)

        return SigVerifyResult(
            verified=True if vsigers else False,
            sigers=vsigers)

    def _validateSenderSeal(self, msg, senderId, **kwa):
        """Validate seal reference attachments against sender's KEL.

        Checks both sscs (seal source couples) and ssts (seal source
        triples, filtered by sender identity) for a valid seal. Tries
        sscs first, then ssts where prefixer matches senderId.

        Per the KRAM spec: "Authentication requires finding the associated
        seal in the referenced event in the Sender's KEL."

        For each candidate seal reference, looks up the event at the
        referenced (sn, said) in the sender's KEL and searches the
        event's seal list for a digest matching the message SAID.

        Parameters:
            msg (SerderKERI): message being authenticated
            senderId (str): sender AID prefix (qb64)
            **kwa: keyword arguments from parser exts dict

        Returns:
            bool: True if seal is valid, False if invalid

        Raises:
            MissingSenderKeyStateError: when a referenced event is not
                found in the sender's KEL (caller should drop + cue)
        """
        # Build list of (number, diger) candidates to check.
        # sscs first (implicit sender KEL ref), then sender-matching ssts.
        candidates = []
        for number, diger in kwa.get('sscs', []):
            candidates.append((number, diger))
        for prefixer, number, diger in kwa.get('ssts', []):
            if prefixer.qb64 == senderId:
                candidates.append((number, diger))

        if not candidates:
            return False

        # Use last candidate per parser convention
        number, diger = candidates[-1]

        # Look up event digest at (senderId, sn) in sender's KEL
        prefixer = coring.Prefixer(qb64=senderId)
        sdig = self.db.kels.getOnLast(keys=prefixer.qb64b, on=number.sn)

        if sdig is None:
            raise kering.MissingSenderKeyStateError(
                f"Event at sn={number.sn} not in KEL for sender {senderId}")

        # Verify the event SAID matches the seal reference
        if bytes(sdig, "utf-8") != diger.qb64b:
            return False  # Event at that sn doesn't match reference

        # Fetch the actual event
        evtSerder = self.db.evts.get(keys=(prefixer.qb64b, bytes(sdig, "utf-8")))
        if evtSerder is None:
            raise kering.MissingSenderKeyStateError(
                f"Event data missing for sender {senderId} at sn={number.sn}")

        # Search event's seal list for a seal whose 'd' field matches msg SAID
        for seal in (evtSerder.seals or []):
            if seal.get('d') == msg.said:
                return True

        return False  # No matching seal digest found


    def _storeNonAuthAttachments(self, key, **kwa):
        """Idempotently store non-authenticator attachments for a partially
        signed multi-key message pending threshold satisfaction.

        Handles all parser kwa attachment keys except ssgs and essrs, which
        are handled separately as authenticators or encapsulations.

        Parameters:
            key (tuple): (AID, MID) partial db key
            **kwa: keyword arguments from parser exts dict
        """
        for item in kwa.get('trqs', []):
            self.db.trqs.add(key, item)
        for prefixer, number, diger, sigers in kwa.get('tsgs', []):
            for siger in sigers:
                self.db.tsgs.add(key, (prefixer, number, diger, siger))
        for item in kwa.get('sscs', []):
            self.db.sscs.add(key, item)
        for item in kwa.get('ssts', []):
            self.db.ssts.add(key, item)
        for item in kwa.get('frcs', []):
            self.db.frcs.add(key, item)
        for item in kwa.get('tdcs', []):
            self.db.tdcs.add(key, item)
        for item in kwa.get('ptds', []):
            self.db.ptds.add(key, item)
        for item in kwa.get('bsqs', []):
            self.db.bsqs.add(key, item)
        for item in kwa.get('bsss', []):
            self.db.bsss.add(key, item)
        for item in kwa.get('tmqs', []):
            self.db.tmqs.add(key, item)


    def _remNonAuthAttachments(self, key):
        """Remove all non-authenticator attachment db entries for key.

        Parameters:
            key (tuple): (AID, MID) partial db key
        """
        self.db.trqs.rem(key)
        self.db.tsgs.rem(key)
        self.db.sscs.rem(key)
        self.db.ssts.rem(key)
        self.db.frcs.rem(key)
        self.db.tdcs.rem(key)
        self.db.ptds.rem(key)
        self.db.bsqs.rem(key)
        self.db.bsss.rem(key)
        self.db.tmqs.rem(key)


    def intake(self, serder, **kwa):
        """Process message through KRAM denial and cache logic.

        Parameters:
            serder (SerderKERI): message instance
            **kwa: keyword arguments from parser exts dict
        """
        if self.enabled:
            md = self.denial(serder)  # message denial string
            for d in self.denials:
                if md.startswith(d):
                    return serder
            return self.kramit(serder, **kwa)
        return serder  # KRAM disabled for all messages return message for further processing


    def kramit(self, msg, **kwa):
        """Core KRAM processing logic.

        Implements timeliness cache checking, auth type detection,
        and cache management for replay attack prevention.

        For exn messages, exchange ID routing is version-gated: v2 exn
        messages use the x field to determine transactioned vs non-transactioned
        routing. v1 exn messages have no x field and are always treated as
        non-transactioned (routed to the msgc cache).

        Parameters:
            msg (SerderKERI): message instance
            **kwa: keyword arguments from parser exts dict containing
                   auth attachments and other parsed data

        Returns:
            SerderKERI: the message if it passes KRAM
            None: if the message fails KRAM or is pending (multi-key)

        Raises:
            MissingAuthAttachmentError: no auth attachments on message
            MissingSenderKeyStateError: sender KEL unavailable
            KramError: general errors used for linter compliance; indicates
                something is very wrong if raised
        """

        senderId = msg.pre
        msgType = msg.ilk
        msgId = msg.said
        route = msg.route
        mdts = msg.stamp
        if not mdts:
            return None  # no datetime, cannot check timeliness
        mdt = helping.fromIso8601(mdts).timestamp() * 1000  # ms

        hasSealRef = self._hasSeals(senderId, **kwa)
        hasSigs = self._hasSigs(senderId, **kwa)

        if not hasSealRef and not hasSigs:
            raise kering.MissingAuthAttachmentError(
                f"No authentication attachments for "
                f"message {msgType} with SAID={msgId}")

        exId = None

        match msgType:
            case kering.Ilks.xip:
                exId = msgId
            case kering.Ilks.exn:
                if msg.pvrsn >= kering.Vrsn_2_0:
                    exId = msg.ked.get('x', None)
            case _:
                pass

        # Non-transactioned-exchange message is checked against the message-ID-based cache database.
        if not exId:
            key = (senderId, msgId)
            cache = self.db.msgc.get(key)

            if cache:  # Existing message-ID-cache processing logic.
                # Determine authentication type (resolve "both attached"
                # special case) then drop or accumulate.

                # Pure seal reference case (no sigs attached)
                if hasSealRef and not hasSigs:
                    # Seal auth is idempotent, cache already exists
                    return None

                # All remaining paths need sender's key state
                kever = self.db.kevers.get(senderId)
                if kever is None:
                    # Append the cue for the keystate retrieval notification including the senderID
                    self.cues.append({
                        "kin": "keystate",
                        "aid": senderId,
                        "sn": kever.sn if kever else None,
                    })
                    logger.info(
                        "Cueing keystate retrieval: missing KEL for sender=%s, current_sn=%s, error=%s",
                        senderId,
                        kever.sn if kever else None,
                    )
                    raise kering.MissingSenderKeyStateError(
                        f"Sender KEL unavailable for {senderId}")

                # "Both attached" case, try seal validation first
                if hasSealRef and hasSigs:
                    if self._validateSenderSeal(msg, senderId, **kwa):
                        # Seal valid -> treat as seal auth -> idempotent drop
                        return None
                    # Seal invalid -> fall through to signature auth below

                # Signature auth: check key list cardinality
                if len(kever.verfers) == 1:
                    # Single-key sig auth is idempotent, cache already exists
                    return None

                # Multi-key signature accumulation.
                # Reached from both "pure sig multi-key" and
                # "both attached with invalid seal, multi-key" paths.

                # Verify attached sigs using type-appropriate dispatch
                sigResult = self._verifyAttachedSigs(
                    msg=msg, senderId=senderId, kever=kever, **kwa)

                if not sigResult.verified:
                    return None  # no valid sigs in this delivery

                # Key state change detection:
                # Compare stored key state ref against current kever state
                currentKeyState = (kever.sner,
                                   coring.Diger(qb64=kever.serder.said))
                storedKeyState = self.db.pmsk.get(key)
                if storedKeyState:
                    storedSn, storedSaid = storedKeyState
                    if (storedSn.num != currentKeyState[0].num or
                            storedSaid.qb64 != currentKeyState[1].qb64):
                        return None  # drop, key state changed

                # Idempotently accumulate newly verified signatures
                existingSigs = self.db.pmks.get(key)
                if existingSigs is None:
                    existingSigs = []

                existingSigIndices = {sig.index for sig in existingSigs}
                newSigs = [sig for sig in sigResult.sigers
                           if sig.index not in existingSigIndices]

                for sig in newSigs:
                    self.db.pmks.add(key, sig)

                # Store message and key state on first verified signature
                if newSigs:
                    if self.db.pmkm.get(key) is None:
                        self.db.pmkm.put(key, msg)

                    if storedKeyState is None:
                        self.db.pmsk.pin(key, currentKeyState)

                    # Store non-auth attachments alongside new sigs
                    self._storeNonAuthAttachments(key, **kwa)                    

                # Check threshold using current kever's tholder
                allSigs = existingSigs + newSigs
                if kever.tholder and len(allSigs) > 0:
                    sigIndices = [sig.index for sig in allSigs]

                    if kever.tholder.satisfy(indices=sigIndices):
                        # Accept, partial database entries will be removed by pruner
                        return msg

                # Threshold not satisfied, message remains pending
                return None

            else:  # New cache logic when no existing cache is found for (AID.MID)
                cacheTypeRecord = self._fetchCacheType(msgType, route)

                kever = self.db.kevers.get(senderId)
                if kever is None:
                    # Append the cue for the keystate retrieval notification including the senderID
                    self.cues.append({
                        "kin": "keystate",
                        "aid": senderId,
                        "sn": kever.sn if kever else None,
                    })
                    logger.info(
                        "Cueing keystate retrieval: missing KEL for sender=%s, current_sn=%s, error=%s",
                        senderId,
                        kever.sn if kever else None,
                    )
                    raise kering.MissingSenderKeyStateError(
                        f"Sender KEL unavailable for {senderId}")

                # Resolve auth type before timeliness check per spec.
                # Ensures "both attached" fallback to multi-key gets long lag.
                authType, sealValidated = self._resolveAuthType(
                    msg, kwa, kever, hasSealRef, hasSigs, senderId)

                # Select lag values based on resolved auth type
                d = cacheTypeRecord.d
                if authType == AuthTypes.AttachedSignatureMultiKey:
                    ml = cacheTypeRecord.ll   # long lag for multi-key
                    pml = cacheTypeRecord.pll
                else:
                    ml = cacheTypeRecord.sl   # short lag for seal/single-key
                    pml = cacheTypeRecord.psl

                # Timeliness check (millisecond units)
                rdt = helping.fromIso8601(
                    helping.nowIso8601()).timestamp() * 1000  # ms

                # We can check timeliness here because we perform this for all auth types and the only difference is
                # the value of ml based on the auth type.
                if not (rdt - d - ml) <= mdt <= (rdt + d):
                    return None  # outside timeliness window

                # Validate/verify by auth type
                if authType == AuthTypes.AttachedSealReference:
                    # Pure seal: validate now. "Both attached" with valid
                    # seal: already validated during _resolveAuthType.
                    if not sealValidated:
                        try:
                            sealValidated = self._validateSenderSeal(
                                msg, senderId, **kwa)
                        except kering.MissingSenderKeyStateError as e:
                            logger.info("Missing sender key state for "
                                        "%s: %s", senderId, e)
                            # Append the cue for the keystate retrieval notification including the senderID and the sn
                            self.cues.append({
                                "kin": "keystate",
                                "aid": senderId,
                                "sn": kever.sn if kever else None,
                            })
                            logger.info(
                                "Cueing keystate retrieval: missing key state in seal reference for sender=%s, current_sn=%s, error=%s",
                                senderId,
                                kever.sn if kever else None,
                            )
                            return None
                        if not sealValidated:
                            return None

                    # Create cache and accept
                    mcr = MsgCacheRecord(
                        mdt=mdts, d=d, ml=ml, pml=pml,
                        xl=cacheTypeRecord.xl, pxl=cacheTypeRecord.pxl)
                    self.db.msgc.pin(key, mcr)
                    return msg

                elif authType == AuthTypes.AttachedSignatureSingleKey:
                    # Verify single-key signature
                    sigResult = self._verifyAttachedSigs(
                        msg=msg, senderId=senderId, kever=kever, **kwa)

                    if not sigResult.verified:
                        return None

                    # Create cache and accept
                    mcr = MsgCacheRecord(
                        mdt=mdts, d=d, ml=ml, pml=pml,
                        xl=cacheTypeRecord.xl, pxl=cacheTypeRecord.pxl)
                    self.db.msgc.pin(key, mcr)
                    return msg

                elif authType == AuthTypes.AttachedSignatureMultiKey:
                    # Verify multi-key signatures
                    sigResult = self._verifyAttachedSigs(
                        msg=msg, senderId=senderId, kever=kever, **kwa)

                    if not sigResult.verified:
                        return None  # no sigs verified at all

                    # Create cache entry (at least one sig verified)
                    mcr = MsgCacheRecord(
                        mdt=mdts, d=d, ml=ml, pml=pml,
                        xl=cacheTypeRecord.xl, pxl=cacheTypeRecord.pxl)
                    self.db.msgc.pin(key, mcr)

                    # Check if threshold is immediately satisfied
                    sigIndices = [sig.index for sig in sigResult.sigers]

                    if kever.tholder and kever.tholder.satisfy(indices=sigIndices):
                        # Threshold met on first delivery, accept
                        return msg

                    # Threshold not met, store partials for accumulation
                    currentKeyState = (kever.sner,
                                       coring.Diger(qb64=kever.serder.said))
                    self.db.pmkm.put(key, msg)
                    for sig in sigResult.sigers:
                        self.db.pmks.add(key, sig)

                    self.db.pmsk.pin(key, currentKeyState)

                    # Store non-auth attachments for forwarding on threshold satisfaction
                    self._storeNonAuthAttachments(key, **kwa)

                    return None  # message pending

        else:  # If we have an exchange id, x field value
            key = (senderId, exId, msgId)
            partialKey = (senderId, msgId)  # partial dbs keyed by (AID.MID) per spec
            cache = self.db.tmsc.get(key)

            if cache:
                # Existing message-ID-cache processing logic.
                # Determine authentication type (resolve "both attached"
                # special case per whitepaper) then drop or accumulate.

                # Pure seal reference case (no sigs attached)
                if hasSealRef and not hasSigs:
                    # Seal auth is idempotent, cache already exists
                    return None

                # All remaining paths need sender's key state
                kever = self.db.kevers.get(senderId)
                if kever is None:
                    # Append the cue for the keystate retrieval notification including the senderID
                    self.cues.append({
                        "kin": "keystate",
                        "aid": senderId,
                        "sn": kever.sn if kever else None,
                    })
                    logger.info(
                        "Cueing keystate retrieval: missing KEL for sender=%s, current_sn=%s, error=%s",
                        senderId,
                        kever.sn if kever else None,
                    )
                    raise kering.MissingSenderKeyStateError(
                        f"Sender KEL unavailable for {senderId}")

                # "Both attached" case, try seal validation first
                if hasSealRef and hasSigs:
                    if self._validateSenderSeal(msg, senderId, **kwa):
                        # Seal valid -> treat as seal auth -> idempotent drop
                        return None
                    # Seal invalid -> fall through to signature auth below

                # Signature auth: check key list cardinality
                if len(kever.verfers) == 1:
                    # Single-key sig auth is idempotent, cache already exists
                    return None

                # Multi-key signature accumulation.
                # Reached from both "pure sig multi-key" and
                # "both attached with invalid seal, multi-key" paths.

                # Verify attached sigs using type-appropriate dispatch
                sigResult = self._verifyAttachedSigs(
                    msg=msg, senderId=senderId, kever=kever, **kwa)

                if not sigResult.verified:
                    return None  # no valid sigs in this delivery

                # Key state change detection:
                # Compare stored key state ref against current kever state.
                # Partial dbs use (AID.MID) key per spec, not (AID.XID.MID).
                currentKeyState = (kever.sner,
                                   coring.Diger(qb64=kever.serder.said))
                storedKeyState = self.db.pmsk.get(partialKey)
                if storedKeyState:
                    storedSn, storedSaid = storedKeyState
                    if (storedSn.num != currentKeyState[0].num or
                            storedSaid.qb64 != currentKeyState[1].qb64):
                        return None  # drop, key state changed

                # Idempotently accumulate newly verified signatures
                existingSigs = self.db.pmks.get(partialKey)
                if existingSigs is None:
                    existingSigs = []

                existingSigIndices = {sig.index for sig in existingSigs}
                newSigs = [sig for sig in sigResult.sigers
                           if sig.index not in existingSigIndices]

                for sig in newSigs:
                    self.db.pmks.add(partialKey, sig)

                # Store message and key state on first verified signature
                if newSigs:
                    if self.db.pmkm.get(partialKey) is None:
                        self.db.pmkm.put(partialKey, msg)

                    if storedKeyState is None:
                        self.db.pmsk.pin(partialKey, currentKeyState)

                    # Store non-auth attachments alongside new sigs
                    self._storeNonAuthAttachments(partialKey, **kwa)                    

                # Check threshold using current kever's tholder
                allSigs = existingSigs + newSigs
                if kever.tholder and len(allSigs) > 0:
                    sigIndices = [sig.index for sig in allSigs]

                    if kever.tholder.satisfy(indices=sigIndices):
                        # Accept, partial database entries will be removed by pruner
                        return msg

                # Threshold not satisfied, message remains pending
                return None

            else:  # New cache logic when no existing cache is found for (AID.XID.MID)
                cacheTypeRecord = self._fetchCacheType(msgType, route)

                kever = self.db.kevers.get(senderId)
                if kever is None:
                    # Append the cue for the keystate retrieval notification including the senderID
                    self.cues.append({
                        "kin": "keystate",
                        "aid": senderId,
                        "sn": kever.sn if kever else None,
                    })
                    logger.info(
                        "Cueing keystate retrieval: missing KEL for sender=%s, current_sn=%s, error=%s",
                        senderId,
                        kever.sn if kever else None,
                    )
                    raise kering.MissingSenderKeyStateError(
                        f"Sender KEL unavailable for {senderId}")

                # Resolve auth type before timeliness check per spec.
                authType, sealValidated = self._resolveAuthType(
                    msg, kwa, kever, hasSealRef, hasSigs, senderId)

                d = cacheTypeRecord.d
                if authType == AuthTypes.AttachedSignatureMultiKey:
                    ml = cacheTypeRecord.ll   # long lag for multi-key
                    pml = cacheTypeRecord.pll
                else:
                    ml = cacheTypeRecord.sl   # short lag for seal/single-key
                    pml = cacheTypeRecord.psl

                if authType == AuthTypes.AttachedSealReference or authType == AuthTypes.AttachedSignatureSingleKey:
                    match msgType:
                        case kering.Ilks.xip:
                            xdts = msg.ked.get('dt', None)
                        case kering.Ilks.exn:
                            # x field value to fetch any existing cache entry with a matching AID.XID and copy its xdt
                            # value. When no existing cache entry is found, then drop the event and exit.
                            existingCache = next(self.db.tmsc.getItemIter((senderId, exId)), None)

                            if existingCache is not None:
                                keys, cacheRecord = existingCache
                                xdts = cacheRecord.xdt
                            else:
                                # No existing cache entry found, drop the event and exit
                                return None
                        case _:
                            # Should never be reaching this case
                            raise kering.KramError("Unexpected transactioned message type while kraming.")

                    xdt = helping.fromIso8601(xdts).timestamp() * 1000  # ms
                    rdt = helping.fromIso8601(
                        helping.nowIso8601()).timestamp() * 1000  # ms

                    if not (rdt - d - ml) <= mdt <= (rdt + d):
                        return None

                    xl = cacheTypeRecord.xl

                    if not (xdt <= mdt <= xdt + xl):
                        return None

                    if authType == AuthTypes.AttachedSealReference:
                        # Pure seal: validate now. "Both attached" with valid
                        # seal: already validated during _resolveAuthType.
                        if not sealValidated:
                            try:
                                sealValidated = self._validateSenderSeal(
                                    msg, senderId, **kwa)
                            except kering.MissingSenderKeyStateError as e:
                                logger.info("Missing sender key state for "
                                            "%s: %s", senderId, e)
                                # Append the cue for the keystate retrieval notification including the senderID and the sn                           
                                self.cues.append({
                                    "kin": "keystate",
                                    "aid": senderId,
                                    "sn": kever.sn if kever else None,
                                })
                                logger.info(
                                    "Cueing keystate retrieval: missing key state in seal reference for sender=%s, current_sn=%s, error=%s",
                                    senderId,
                                    kever.sn if kever else None,
                                )
                                return None
                            if not sealValidated:
                                return None

                        # Create txn cache and accept
                        mcr = TxnMsgCacheRecord(
                            mdt=mdts, xdt=xdts, d=d, ml=ml, pml=pml,
                            xl=cacheTypeRecord.xl, pxl=cacheTypeRecord.pxl)
                        self.db.tmsc.pin(key, mcr)
                        return msg

                    elif authType == AuthTypes.AttachedSignatureSingleKey:
                        # Verify single-key signature
                        sigResult = self._verifyAttachedSigs(
                            msg=msg, senderId=senderId, kever=kever, **kwa)

                        if not sigResult.verified:
                            return None

                        # Create txn cache and accept
                        mcr = TxnMsgCacheRecord(
                            mdt=mdts, xdt=xdts, d=d, ml=ml, pml=pml,
                            xl=cacheTypeRecord.xl, pxl=cacheTypeRecord.pxl)
                        self.db.tmsc.pin(key, mcr)
                        return msg

                elif authType == AuthTypes.AttachedSignatureMultiKey:
                    # Per spec: for multi-key, mdt timeliness check comes before xdt resolution
                    rdt = helping.fromIso8601(
                        helping.nowIso8601()).timestamp() * 1000  # ms

                    if not (rdt - d - ml) <= mdt <= (rdt + d):
                        return None  # outside mdt timeliness window

                    # Resolve xdt after mdt check
                    match msgType:
                        case kering.Ilks.xip:
                            xdts = msg.ked.get('dt', None)
                        case kering.Ilks.exn:
                            existingCache = next(
                                self.db.tmsc.getItemIter((senderId, exId)),
                                None)
                            if existingCache is not None:
                                keys, cacheRecord = existingCache
                                xdts = cacheRecord.xdt
                            else:
                                return None  # no existing cache, drop
                        case _:
                            raise kering.KramError(
                                "Unexpected transactioned message type "
                                "while kraming.")

                    xdt = helping.fromIso8601(xdts).timestamp() * 1000
                    xl = cacheTypeRecord.xl

                    if not (xdt <= mdt <= xdt + xl):
                        return None  # outside exchange window

                    # Verify multi-key signatures
                    sigResult = self._verifyAttachedSigs(
                        msg=msg, senderId=senderId, kever=kever, **kwa)

                    if not sigResult.verified:
                        return None  # no sigs verified at all

                    # At least one sig verified, create txn cache entry
                    mcr = TxnMsgCacheRecord(
                        mdt=mdts, xdt=xdts, d=d, ml=ml, pml=pml,
                        xl=cacheTypeRecord.xl, pxl=cacheTypeRecord.pxl)
                    self.db.tmsc.pin(key, mcr)

                    # Check if threshold is immediately satisfied
                    sigIndices = [sig.index for sig in sigResult.sigers]

                    if kever.tholder and kever.tholder.satisfy(indices=sigIndices):
                        # Threshold met on first delivery, accept
                        return msg

                    # Threshold not met, store partials for accumulation.
                    # Partial dbs use (AID.MID) key per spec, not (AID.XID.MID).
                    currentKeyState = (kever.sner,
                                       coring.Diger(qb64=kever.serder.said))
                    self.db.pmkm.put(partialKey, msg)
                    for sig in sigResult.sigers:
                        self.db.pmks.add(partialKey, sig)

                    self.db.pmsk.pin(partialKey, currentKeyState)

                    # Store non-auth attachments for forwarding on threshold satisfaction
                    self._storeNonAuthAttachments(partialKey, **kwa)

                    return None  # message pending
                else:
                    raise kering.KramError("Unexpected auth type while kraming.")
