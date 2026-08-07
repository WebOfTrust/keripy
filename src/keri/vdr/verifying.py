# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.verifying module

VC verifier support
"""
import datetime
import logging
from typing import Type

from hio.help import decking, ogler

from ..kering import (Ilks, MissingChainError,
                      MissingRegistryError, MissingSchemaError,
                      ValidationError, FailedSchemaValidationError,
                      MissingChainError, RevokedChainError)
from ..core import Dater, Saider, Parser, CacheResolver, Schemer
from ..help import helping

from .eventing import Tevery, Reger, query

logger = ogler.getLogger()


class Verifier:
    """
    Verifier class accepts and validates TEL events.

    """
    TimeoutPSE = 3600  # seconds to timeout partially signed credential escrow
    TimeoutMRE = 3600  # seconds to timeout missing registry escrows
    TimeoutMRI = 3600  # seconds to timeout missing issuer escrows
    TimeoutBCE = 3600  # seconds to timeout missing issuer escrows

    # Unary edge operators this verifier recognizes. A token outside this set is not an
    # operator to this verifier and is skipped when resolving a list-valued `o` (see
    # .verifyChain). NOT is recognized but unimplemented (#1554): it is listed so it fails
    # closed diagnosably instead of being dropped and silently defaulting.
    # E1E is a keripy extension not yet in the spec's normative operator table.
    UnaryOps = ('I2I', 'NI2I', 'DI2I', 'E1E', 'NOT')

    # The delegative subset of .UnaryOps: each constrains the near ACDC's issuer
    # relative to the far node's issuee, so they are mutually exclusive and a list
    # containing several is a conflict resolved latest-wins. Operators outside this
    # subset constrain something else and compose with the winner instead.
    DelegativeOps = ('I2I', 'NI2I', 'DI2I')

    def __init__(self, hby, reger=None, creds=None, cues=None, expiry=36000000000):
        """
        Initialize Verifier instance

        Parameters:
            hby (Habery): for this verifier's context
            reger (Reger): database instance
            creds (decking.Deck): inbound credentials for handler
            cues (decking.Deck): outbound cue messages from handler

        """
        self.hby = hby
        self.reger = reger if reger is not None else Reger(name=self.hby.name, temp=self.hby.temp)
        self.creds = creds if creds is not None else decking.Deck()  # subclass of deque
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque
        self.CredentialExpiry = expiry

        self.inited = False
        self.tvy = None
        self.psr = None
        self.resolver = None

        if self.hby.inited:
            self.setup()

    def setup(self):
        """ Delayed initialization of instance by createing .tvy and .psr.

        Should not be called until .hab is initialized

        """
        self.tvy = Tevery(reger=self.reger, db=self.hby.db, local=False)
        self.psr = Parser(framed=True, kvy=self.hby.kvy, tvy=self.tvy,
                                  version=self.hby.version)
        self.resolver = CacheResolver(db=self.hby.db)

        self.inited = True

    @property
    def tevers(self):
        """ Returns .db.tevers
        """
        return self.reger.tevers

    def processMessages(self, creds=None):
        """ Process message dicts in msgs or if msgs is None in .msgs

        Parameters:
            creds (decking.Deck): each entry is dict that matches call signature of
                .processCredential
        """
        if creds is None:
            creds = self.creds

        while creds:
            self.processCredential(**creds.pull())


    def processCredential(self, creder, prefixer, seqner, saider, **kwa):
        """ Credential data and signature(s) verification

        Verify the data of the credential against the schema, the SAID of the credential and
        the CESR Proof on the credential and if valid, store the credential

        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix of source anchoring KEL or TEL event
            seqner (Seqner): sequence number of source anchoring KEL or TEL event
            saider (Saider): SAID of source anchoring KEL or TEL event

        """
        regk = creder.regid
        vcid = creder.said
        schema = creder.schema
        prov = creder.edge if creder.edge is not None else {}

        if regk not in self.tevers:  # registry event not found yet
            if self.escrowMRE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk, i=vcid, issr=creder.israid)))
            raise MissingRegistryError("registry identifier {} not in Tevers".format(regk))

        state = self.tevers[regk].vcState(vcid)
        if state is None:  # credential issuance event not found yet
            if self.escrowMRE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk, i=vcid)))
            raise MissingRegistryError("credential identifier {} not in Tevers".format(vcid))

        dtnow = helping.nowUTC()
        dte = helping.fromIso8601(state.dt)
        if (dtnow - dte) > datetime.timedelta(seconds=self.CredentialExpiry):
            if self.escrowMRE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk, i=vcid)))
            raise MissingRegistryError("credential identifier {} is out of date".format(vcid))
        elif state.et in (Ilks.rev, Ilks.brv):  # no escrow, credential has been revoked
            logger.error("credential {} in registrying is not in issued state".format(vcid, regk))
            # Log this and continue instead of the previous exception so we save a revoked credential.
            # raise InvalidCredentialStateError("..."))

        # Verify the credential against the schema
        scraw = self.resolver.resolve(schema)
        if not scraw:
            if self.escrowMSE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="query", q=dict(r="schema", said=schema)))
            raise MissingSchemaError("schema {} not in cache".format(schema))

        schemer = Schemer(raw=scraw)
        try:
            schemer.verify(creder.raw)
        except ValidationError as ex:
            print("Credential {} is not valid against schema {}: {}"
                  .format(creder.said, schema, ex))
            raise FailedSchemaValidationError("Credential {} is not valid against schema {}: {}"
                                                     .format(creder.said, schema, ex))

        if isinstance(prov, list):
            edges = prov
        elif isinstance(prov, dict):
            edges = [prov]
        else:
            print(f"Invalid type for edges: {prov}")
            raise ValidationError(f"invalid type for edges: {prov}")

        for edge in edges:
            for label, node in edge.items():
                if label in ('d', 'o'):  # SAID or Operator of this edge block
                    continue
                nodeSaid = node["n"]
                op = node['o'] if 'o' in node else None
                try:
                    state = self.verifyChain(nodeSaid, op, creder.israid, creder.iseaid)
                except ValidationError as ex:
                    # .verifyChain knows the far node but not the near credential that
                    # carried the edge, and the escrow handler logs only the exception.
                    # Re-raise with the near SAID and edge label so an operator triaging
                    # a stream can tell which credential to fix, matching the shape of
                    # the MissingChainError messages below.
                    raise ValidationError(f"Failure to verify credential {creder.said} "
                                          f"chain {label}({nodeSaid}): {ex}") from ex
                if state is None:
                    self.escrowMCE(creder, prefixer, seqner, saider)
                    self.cues.append(dict(kin="proof",  said=nodeSaid))
                    raise MissingChainError("Failure to verify credential {} chain {}({})"
                                                   .format(creder.said, label, nodeSaid))

                # Enforce the edge's declared far-node schema ('s'). Per ACDC (S.
                # Smith, issue #1534) the edge 's' is a schema the far node must
                # *satisfy*, not a SAID that must equal the far node's own schema
                # SAID. The far node already validated against its own schema (it is
                # saved, per verifyChain above), so an edge declaring that same
                # schema needs no further check. When the edge declares a *different*
                # schema, the far node must additionally satisfy it: if it does, the
                # near side is legitimately requiring a backwards-compatible (e.g.
                # upgraded) schema without the far node being reissued; if it does
                # not, the edge schema is not backwards compatible and the far node
                # must be reissued. Handled here rather than in verifyChain so the
                # missing-schema case can escrow and cue a schema query, exactly as
                # the near ACDC's own schema does above.
                nodeSchema = node['s'] if 's' in node else None
                if nodeSchema is not None:
                    farCreder = self.reger.creds.get(keys=nodeSaid)
                    if farCreder.schema != nodeSchema:
                        scraw = self.resolver.resolve(nodeSchema)
                        if not scraw:  # edge schema not cached yet -- transient
                            if self.escrowMSE(creder, prefixer, seqner, saider):
                                self.cues.append(dict(kin="query",
                                                      q=dict(r="schema", said=nodeSchema)))
                            raise MissingSchemaError("edge schema {} for credential {} "
                                                     "chain {}({}) not in cache"
                                                     .format(nodeSchema, creder.said,
                                                             label, nodeSaid))
                        try:
                            Schemer(raw=scraw).verify(farCreder.raw)
                        except ValidationError as ex:  # far node fails the edge schema
                            self.escrowMCE(creder, prefixer, seqner, saider)
                            self.cues.append(dict(kin="proof", said=nodeSaid))
                            raise MissingChainError("Credential {} chain {}({}) far node "
                                                    "does not satisfy edge schema {}: {}"
                                                    .format(creder.said, label, nodeSaid,
                                                            nodeSchema, ex))

                dtnow = helping.nowUTC()
                dte = helping.fromIso8601(state.dt)
                if (dtnow - dte) > datetime.timedelta(seconds=self.CredentialExpiry):
                    self.escrowMCE(creder, prefixer, seqner, saider)
                    self.cues.append(dict(kin="query", q=dict(r="tels", pre=nodeSaid)))
                    raise MissingChainError("Failure to verify credential {} chain {}({})"
                                                   .format(creder.said, label, nodeSaid))
                elif state.et in (Ilks.rev, Ilks.brv):
                    raise RevokedChainError("Failure to verify credential {} chain {}({})"
                                                   .format(creder.said, label, nodeSaid))
                else:  # VcStatus == VcStates.Issued
                    logger.info("Successfully validated credential chain {} for credential {}"
                                .format(label, creder.said))

        self.saveCredential(creder, prefixer, seqner, saider)
        self.cues.append(dict(kin="saved", creder=creder))

    def processACDC(self, **kwa):
        """Alias of .processCredential with Parser compatible call signature

        Parameters:
            serder (SerderACDC): ACDC to process
            prefixer (Prefixer): prefix of source anchoring KEL or TEL event
            seqner (Seqner): sequence number of source anchoring KEL or TEL event
            saider (Saider): SAID of source anchoring KEL or TEL event

        """
        creder = kwa['serder']
        kwa['creder'] = creder
        del kwa['serder']
        self.processCredential(**kwa)


    def escrowMRE(self, creder, prefixer, seqner, saider):
        """ Missing Registry Escrow

        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix (AID or TEL) of event anchoring credential
            seqner (Seqner): sequence number of event anchoring credential
            saider (Diger) digest of anchoring event for credential

        """
        key = creder.said

        self.reger.logCred(creder, prefixer, seqner, saider)
        return self.reger.mre.put(keys=key, val=Dater())

    def escrowMCE(self, creder, prefixer, seqner, saider):
        """ Missing Chain Escrow

        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix (AID or TEL) of event anchoring credential
            seqner (Seqner): sequence number of event anchoring credential
            saider (Diger) digest of anchoring event for credential

        """
        key = creder.said

        self.reger.logCred(creder, prefixer, seqner, saider)
        return self.reger.mce.put(keys=key, val=Dater())

    def escrowMSE(self, creder, prefixer, seqner, saider):
        """
        Missing Credential Schema Escrow


        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix (AID or TEL) of event anchoring credential
            seqner (Seqner): sequence number of event anchoring credential
            saider (Diger) digest of anchoring event for credential

        """
        key = creder.said

        self.reger.logCred(creder, prefixer, seqner, saider)
        return self.reger.mse.put(keys=key, val=Dater())

    def processEscrows(self):
        """ Process all escrows once each

        """

        self._processEscrow(self.reger.mce, self.TimeoutMRI, MissingChainError)
        self._processEscrow(self.reger.mse, self.TimeoutMRI, MissingSchemaError)
        self._processEscrow(self.reger.mre, self.TimeoutMRE, MissingRegistryError)

    def _processEscrow(self, db, timeout, etype: Type[Exception]):
        """ Generic credential escrow processing

        Parameters:
            db (LMDBer): escrow database table to process
            timeout (float): escrow specific message timeout
            etype (TypeOf(Exception)): exception class to catch and ignore

        """
        for (said,), dater in db.getTopItemIter():
            creder, prefixer, seqner, saider = self.reger.cloneCred(said)

            try:

                dtnow = helping.nowUTC()
                dte = helping.fromIso8601(dater.dts)
                if (dtnow - dte) > datetime.timedelta(seconds=timeout):
                    # escrow stale so raise ValidationError which unescrows below
                    logger.info("Verifier unescrow error: Stale event escrow "
                                " at said = %s", said)

                    raise ValidationError("Stale event escrow "
                                                 "at said = {}.".format(said))

                self.processCredential(creder, prefixer, seqner, saider)

            except etype as ex:
                # Log the exception, not ex.args[0]: an exception raised with no
                # arguments has an empty args tuple, so indexing it would raise
                # IndexError from inside this handler and abort the whole pass.
                if logger.isEnabledFor(logging.TRACE):
                    logger.trace("Verifier unescrow failed: %s\n", ex)
                    logger.exception("Verifier unescrow failed: %s\n", ex)
            except Exception as ex:  # log diagnostics errors etc
                # error other than missing sigs so remove from PA escrow
                db.rem(said)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Verifier unescrowed: %s", ex)
                else:
                    logger.error("Verifier unescrowed: %s", ex)
            else:
                db.rem(said)
                logger.info("Verifier: unescrow succeeded in valid group op: creder=%s", creder.said)
                logger.debug(f"#vent=\n%s\n", creder.pretty())

    def saveCredential(self, creder, prefixer, seqner, saider):
        """ Write the credential and associated indicies to the database

        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix (AID or TEL) of event anchoring credential
            seqner (Seqner): sequence number of event anchoring credential
            saider (Diger) digest of anchoring event for credential

        """
        self.reger.logCred(creder, prefixer, seqner, saider)

        schema = creder.schema.encode("utf-8")
        issuer = creder.israid.encode("utf-8")

        # Look up indicies
        saider = Saider(qb64=creder.said)
        self.reger.saved.pin(keys=saider.qb64b, val=saider)
        self.reger.issus.add(keys=issuer, val=saider)
        self.reger.schms.add(keys=schema, val=saider)

        # Resolve the issuee via .iseaid so aggregate ('acg') credentials index
        # their subject too: for them .attrib is None and the issuee lives at
        # .sad["A"][1]["i"]. For attributive creds .iseaid == .attrib["i"].
        if creder.iseaid is not None:
            subject = creder.iseaid.encode("utf-8")
            self.reger.subjs.add(keys=subject, val=saider)

    def query(self, pre, regk, vcid, *, dt=None, dta=None, dtb=None, **kwa):
        """ Returns query message for querying registry
        """

        serder = query(pre=pre, regk=regk, vcid=vcid, dt=dt, dta=dta,
                       dtb=dtb, **kwa)
        hab = self.hby.habs[pre]
        return hab.endorse(serder, last=True, framed=False, gvrsn=serder.pvrsn)

    def verifyChain(self, nodeSaid, op, issuer, issuee=None):
        """ Verifies the node credential at the end of an edge

        Parameters:
            nodeSaid: (str): qb64 SAID of node credential
            op (str|list|None): edge operator, or a list of unary operators, in which
                case the latest recognized one takes precedence. None, an empty list,
                or a value containing no recognized operator applies the default:
                I2I for a targeted far node, NI2I for an untargeted one.
            issuer (str) qb64 AID of the issuer of the near (edge-bearing) ACDC. The
                delegative operators (I2I, DI2I) constrain this against the far node's
                issuee.
            issuee (str|None): qb64 AID of the issuee of the near (edge-bearing) ACDC,
                required by the identity operators (E1E). None when the near ACDC is
                untargeted.

        Returns:
            Serder|None: transaction event state notification message for the far node,
                or None if the edge does not verify. None is a validation outcome, not an
                error: processCredential turns it into a missing-chain escrow and retry.

        """
        said = self.reger.saved.get(keys=nodeSaid)
        if said is None:
            return None

        creder = self.reger.creds.get(keys=nodeSaid)  # far (node) credential

        # `o` is either a single unary operator or a list of them. Latest-wins applies
        # only "among the conflicting Operators" (ACDC spec-body.md L1186), so the list
        # is resolved in two parts: the delegative operators constrain the same thing
        # (the near issuer relative to the far issuee) and therefore conflict, so the
        # latest of those wins; E1E constrains the near issuee instead, so it does not
        # conflict with them and composes (AND) rather than overriding or being
        # overridden. Tokens this verifier does not recognize are skipped.
        ops = op if isinstance(op, (list, tuple)) else [op]
        ops = [cand for cand in ops if cand in self.UnaryOps]
        op = next((cand for cand in reversed(ops) if cand in self.DelegativeOps), None)

        if not ops:  # absent, empty, or nothing recognized: apply the default rule
            # A far node is targeted (I2I) iff it has an issuee, else untargeted (NI2I).
            # Resolve via .iseaid so an aggregate ('acg') far node -- whose issuee is at
            # .sad["A"][1]["i"] and whose .attrib is None -- coerces the same as an
            # attributive one (#1529).
            op = 'I2I' if creder.iseaid is not None else 'NI2I'

        # Recognized but unimplemented operators fail closed with a diagnosable error
        # rather than being silently dropped from the effective list. Deliberately not
        # a MissingChainError: the chain is present and retrying cannot help, so
        # escrowing would promise a retry that can never succeed.
        if 'NOT' in ops:
            raise ValidationError(f"Unsupported edge operator NOT on edge to node "
                                  f"{nodeSaid}; NOT validation is not implemented")

        if 'E1E' in ops:
            # Identity relation (discussion #1515): the issuee AID of the near ACDC
            # (the one carrying this edge) MUST equal the issuee AID of the far node.
            # Unlike the delegative I2I, this says nothing about the issuer, so the
            # common SEDI case -- both credentials issued by a third party to the same
            # subject, issuer != issuee -- is valid (and is exactly what I2I rejects).
            # Resolve the far issuee via .iseaid so an aggregate node (A[1].i) works too.
            farIssuee = creder.iseaid
            if farIssuee is None or issuee is None or issuee != farIssuee:
                return None

        if op == 'DI2I':
            # Delegated-issuer relation (ACDC spec-body.md L1194): the near ACDC's issuer
            # MUST be "either the Issuee AID or a delegated AID" of the far node's issuee.
            # So DI2I is a superset of I2I -- issuer == farIssuee satisfies it outright --
            # and the delegation arm admits only *direct* delegates.
            #
            # Direct-only is the requirement, not an approximation of a transitive walk.
            # The motivating case (#1559) is a QVI that delegates to subgroup AIDs which
            # perform routine issuance: "any number of children, zero grandchildren". A
            # transitive reading would let a subgroup delegate onward and mint new issuers,
            # defeating it. Hence no walk here -- and hence no depth bound, which would be
            # a conformance seam letting two conforming validators disagree on identical
            # bytes with no wire-visible cause.
            #
            # Resolved through .iseaid rather than .attrib['i'] so an aggregate ('A') far
            # node works: .attrib is None there, so `'i' in creder.attrib` would raise
            # TypeError. Deliberately not routed through the .reger.subjs lookup the I2I
            # branch below uses either -- saveCredential only indexes subjects out of the
            # attribute section, so that index is attributive-only by construction.
            farIssuee = creder.iseaid
            if farIssuee is None:  # untargeted far node: no issuee to be a delegate of
                return None

            if issuer != farIssuee and not self._isApprovedDelegate(issuer, farIssuee):
                return None

        elif op is not None and op != 'NI2I':
            # Resolve the far node's issuee via .iseaid so an aggregate ('acg') far
            # node (issuee at .sad["A"][1]["i"]) resolves identically to an
            # attributive one (.attrib["i"]). None means an untargeted far node,
            # which cannot satisfy a targeted (I2I) edge (#1529).
            farIssuee = creder.iseaid
            if farIssuee is None:
                return None

            iss = self.reger.subjs.get(keys=farIssuee)
            if iss is None:
                return None

            if op == 'I2I' and issuer != farIssuee:
                return None

        if creder.regid not in self.tevers:
            return None

        tever = self.tevers[creder.regid]

        state = tever.vcState(nodeSaid)
        if state is None:
            return None

        return state

    def _isApprovedDelegate(self, pre, delpre):
        """Returns True if pre is a direct delegate of delpre, approved by delpre.

        Direct only: the relation is not followed transitively, so a delegate of a
        delegate of delpre returns False. See .verifyChain's DI2I branch for why that is
        the requirement rather than a simplification.

        Deliberately NOT implemented as ``kevers[pre].delpre == delpre``.
        ``Kevery.validateDelegation`` returns early -- with no seal lookup whatsoever --
        when the delegated event is locally owned, locally membered, or locally witnessed
        (core/eventing.py:3287-3289), and the comment there is explicit that a witness
        "accepts without waiting for delegation seal to be anchored in delegator's KEL".
        Since setupWitness co-locates a credential Verifier in the same Habery, a
        delpre-based check would accept a DI2I edge for any AID this Habery happens to
        witness whose claimed delegator never anchored anything: issuance under authority
        never granted. ``delpre`` records what the delegate asserted in its own `di` field;
        only the delegator's anchored approval seal records what the delegator agreed to.

        So the delegation is confirmed the way the KEL layer confirms it, by delegating to
        Kever.fetchDelegatingEvent: consult the approval source-seal couple in .db.aess --
        which logEvent writes only when validateDelegation actually found and verified the
        seal, since the exemption returns (None, None) and that write is gated on those
        being present -- and failing that, walk the delegator's KEL for the anchoring seal
        directly. The walk is what keeps a Habery with no .aess entry (a witness, or the
        delegate's own controller) from being permanently unable to validate an edge that
        is in fact approved.

        .aess is also pinned by flows in which this Habery participated in the delegation
        itself (app/delegating.py:153, app/grouping.py:216,
        app/cli/commands/delegate/confirm.py:109). Each pins it only after observing the
        delegator's anchor, and such a Habery already trusts the delegation, so treating
        the entry as authority-bearing is sound there too.

        Called with original=False so that a missing seal returns None rather than raising,
        and so an inconsistent .aess entry is left alone: a verifier reads key state, it
        does not repair the delegate's escrow. The one write this can cause is
        fetchDelegatingEvent pinning the couple it has just verified against the
        delegator's trunk -- the same cache repair keripy performs during escrow
        processing, gated on the delegated event already having been accepted. A
        ValidationError from a genuinely inconsistent database is left to propagate rather
        than being flattened into a silent False.

        Superseding is handled as the KEL layer handles it, not more strictly. The .aess
        fast path accepts a delegating event that was first seen (it checks .fons) even if
        it has since been superseded -- fetchDelegatingEvent documents that as deliberate --
        while the KEL walk looks only at the last event at each sn and so would not find
        one. Inheriting that asymmetry is the right call rather than something to tighten
        here: a validator that has accepted the delegate's KEL should not then refuse the
        credentials that delegate issued, and DI2I asks the same question the KEL layer
        already answered.

        Retirement of a subgroup is deliberately not modelled at all. It is key-state
        based: a retired delegate rotates to keys it cannot sign with, so it issues nothing
        further while everything it issued while authorized stays valid, and the approval
        seals are byte-identical before and after (#1559). A check here that tried to detect
        retirement would both fail (nothing changes structurally) and be wrong (it would
        invalidate credentials issued while the subgroup was legitimately authorized).

        Parameters:
            pre (str): qb64 AID whose delegation is in question, i.e. the issuer of the
                near (edge-bearing) ACDC
            delpre (str): qb64 AID that must be its delegator, i.e. the far node's issuee

        Returns:
            bool: True means pre is a direct delegate of delpre and delpre's approval of
                pre's current key state is anchored in delpre's KEL.

        """
        if pre not in self.hby.kevers:  # no key state for the issuer, nothing to evaluate
            return False

        kever = self.hby.kevers[pre]
        if kever.delpre is None or kever.delpre != delpre:
            return False

        # The delegation is settled at inception and does not move afterwards. `di` appears
        # in a `dip` and in no other event -- a `drt` has no such field -- so the delegator
        # anchoring the `dip` is the whole of what makes `pre` a delegated AID of `delpre`,
        # and no later event can change or renew it.
        #
        # An earlier version keyed on `kever.lastEst.d`, which asks whether the delegate's
        # *current* establishment event is approved. That is a real question and it is the
        # KEL layer's: `Kevery.validateDelegation` already refuses an unanchored `drt` for
        # every validator outside its locallyOwned/locallyMembered/locallyWitnessed
        # short-circuit. Asking it again here bought nothing and made a fixed edge unstable,
        # because inside that exemption the rotation is accepted locally, `lastEst` advances,
        # and credentials the delegate issued while approved began to be refused. A
        # compromised delegate is answered by cooperative superseding recovery, not by an
        # edge operator changing its verdict.
        #
        # A delegated AID's prefix is a digest of its own `dip` (enforced for `dip` and
        # `drt` by the digestive-prefix requirement in serdering), so `i` equals `d` there
        # and the `dip` is retrievable at (pre, pre).
        serder = self.hby.db.evts.get(keys=(pre, pre))
        if serder is None:  # delegated inception event not retrievable
            return False

        return kever.fetchDelegatingEvent(delpre=delpre, serder=serder,
                                          original=False, eager=True) is not None
