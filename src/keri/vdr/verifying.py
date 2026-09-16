# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.verifying module

VC verifier support
"""
import datetime
import logging
from collections import namedtuple
from typing import Type

from hio.help import decking, ogler

from ..kering import (Ilks, MissingChainError,
                      MissingRegistryError, MissingSchemaError,
                      ValidationError, FailedSchemaValidationError,
                      MissingChainError, RevokedChainError,
                      EdgeRefusalError, UnsupportedOperatorError)
from ..core import Dater, Saider, Parser, CacheResolver, Schemer
from ..help import helping
from ..acdc import chaining

from .eventing import Tevery, Reger, query, walkEdgeSection

logger = ogler.getLogger()

EdgeCause = namedtuple("EdgeCause", "exc cue escrow")
"""What one member verdict tells .disposeSection to do if that member decides.

Carried through the reduction as an EdgeVerdict cause, so the disposition acts on
exactly the members that survived to decide the Edge Section rather than on every
edge it happened to walk.

Fields:
    exc (Exception): what to raise. The class is part of the contract -- an edge
        that does not hold (EdgeRefusalError), one this validator cannot evaluate
        (UnsupportedOperatorError), a far node not yet in hand (MissingChainError)
        and a pin not yet cached (MissingSchemaError) are four different claims, and
        .processEscrows keys its retry tables on the last two.
    cue (dict|None): the query that would resolve this member, or None when nothing
        would.
    escrow (callable|None): the escrow this member belongs in -- .escrowMCE or
        .escrowMSE -- or None when the member is decided and must not be retried.
"""


class Verifier:
    """
    Verifier class accepts and validates TEL events.

    """
    TimeoutPSE = 3600  # seconds to timeout partially signed credential escrow
    TimeoutMRE = 3600  # seconds to timeout missing registry escrows
    TimeoutMRI = 3600  # seconds to timeout missing issuer escrows
    TimeoutBCE = 3600  # seconds to timeout missing issuer escrows

    # Unary edge operators this verifier recognizes. A token outside this set cannot be
    # evaluated, so an edge carrying one is refused rather than validated under a
    # substituted operator -- see .verifyChain. DI2I and NOT are recognized but
    # unimplemented, and refused for the same reason.
    # E1E is normative on the spec's v1.1 branch (kswg-acdc-specification#197). It is
    # absent from the 1.0 text currently under ToIP ratification, so a validator built
    # against 1.0 alone will not recognize it.
    UnaryOps = ('I2I', 'NI2I', 'DI2I', 'E1E', 'NOT')

    # The delegative subset of .UnaryOps: each constrains the near ACDC's issuer
    # relative to the far node's issuee, so they are mutually exclusive and a list
    # containing several is a conflict resolved latest-wins. Operators outside this
    # subset constrain something else and compose with the winner instead.
    DelegativeOps = ('I2I', 'NI2I', 'DI2I')

    # M-ary (aggregating) Operators from the ACDC spec's normative Edge-group table
    # (spec-body.md, "##### Operator, `o` field" under "#### Edge-group"). These
    # apply to an Edge-group's members, not to a single edge, and are therefore
    # disjoint from .UnaryOps. A token outside this set is not an m-ary Operator to
    # this verifier and fails closed -- see .verifyGroup.
    MAryOps = ('AND', 'OR', 'NAND', 'NOR', 'AVG', 'WAVG')

    # The subset of .MAryOps this verifier reduces lives in acdc.chaining, which both
    # this stack and the v2 IPEX path share -- AND and NAND meaning different things
    # on the two paths is the divergence that module exists to end. NAND, NOR, AVG
    # and WAVG are recognized and not reduced: a group asking for one is unknown
    # rather than silently treated as AND, which would apply a weaker rule than the
    # Issuer specified.
    MAryOpsImplemented = tuple(sorted(chaining.MAryReducers))

    # Operator applied to an Edge-group whose `o` field is absent: "When the
    # Operator, `o`, field is missing in an Edge-group block, the default value for
    # the Operator, `o`, field MUST be the `AND` Operator."
    DefaultMAryOp = 'AND'

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

        # Each Edge Section block reduces to one verdict, and a credential carrying
        # several is satisfied only when every one of them is -- the same conjunction
        # a list-valued `e` has always meant here.
        verdict = chaining.reduceAnd([self.evaluateSection(edge, creder)
                                      for edge in edges])
        self.disposeSection(verdict, creder, prefixer, seqner, saider)

        self.saveCredential(creder, prefixer, seqner, saider)
        self.cues.append(dict(kin="saved", creder=creder))

    def evaluateSection(self, edge, creder):
        """ Returns the EdgeVerdict of one Edge Section block, reduced per group

        An Edge Section is itself an Edge-group and MAY nest further Edge-groups, so
        walk it rather than assuming every non-reserved label at the top level is a
        flat edge. Every Edge found, at any depth, evaluates to a member verdict;
        every Edge-group reduces its members under its own m-ary Operator; and the
        section's own reduction is the value returned. Nothing is disposed of here --
        that happens once, in .disposeSection, on the reduced verdict.

        The walk is pre-order, so a group is yielded before its children and every
        parent's schema pins are in place before its children are reached. Walking
        the groups back in reverse therefore reduces each one only after every group
        beneath it has already reduced into it.

        Parameters:
            edge (dict): one Edge Section block from the near credential's `e` field
            creder (Creder): the near (edge-bearing) credential

        Raises:
            ValidationError: the section is malformed -- an Edge-group whose `o` is
                not a single Operator token, an Edge-group with no members, a schema
                pin this verifier cannot resolve to a SAID, or nesting past
                .MaxEdgeGroupDepth. None of these is a truth value: a malformed shape
                says the ACDC is not well-formed, not that some member's validity is
                unknown, so it aborts the section before any reduction runs. Letting
                one into the lattice would make OR(valid, malformed) accept -- a
                well-formedness failure outvoted by a sibling.

        """
        # Schema pins in force at each walked path. An Edge-group MAY carry `s`, a
        # schema every edge below it must satisfy -- a keripy extension (ACDC
        # reserves [d, u, o, w] on a group, spec-body.md:1076-1083) that the v2 IPEX
        # path already honours and inherits (acdc/ipexing.py:875). Only nested groups
        # carry one, matching that path, which reads no pin from the Edge Section
        # itself.
        pins = {}
        members = {}  # path of an Edge-group -> its members' verdicts, in order
        groups = []   # every Edge-group in pre-order, so reversed() is children-first

        for path, node, group in walkEdgeSection(edge):
            if group:
                self.verifyGroup(node, path, creder)
                inherited = pins[path[:-1]] if path else ()
                own = ()
                if path and 's' in node:
                    pin = node['s']
                    if not isinstance(pin, str):
                        # A pin this verifier cannot resolve to a schema SAID must
                        # not be dropped: dropping it accepts the far nodes the pin
                        # exists to exclude. v1 resolves by SAID, so the inline
                        # schema-document form the v2 path accepts is not usable
                        # here. Malformed, so not a verdict.
                        raise ValidationError(f"Edge-group schema pin at "
                                              f"{'.'.join(path)} in credential "
                                              f"{creder.said} is not a schema SAID: "
                                              f"{type(pin).__name__}")
                    own = (pin,)
                pins[path] = inherited + own
                members.setdefault(path, [])
                groups.append((path, node))
                continue

            members.setdefault(path[:-1], []).append(
                self.evaluateEdge(path, node, pins, creder))

        verdict = None
        for path, node in reversed(groups):
            verdict = self.reduceGroup(members[path], node, path, creder)
            if path:
                members[path[:-1]].append(verdict)

        if verdict is None:
            # A compact Edge Section is just its SAID, so .walkEdgeSection yields
            # nothing and there is no group to reduce. Resolving one means
            # dereferencing an Edge block keripy does not store apart from the ACDC
            # that carries it, which is out of scope here and out of scope before
            # this change too.
            return chaining.valid(f"credential {creder.said} carries a compact edge "
                                  f"section, which is not walked")

        return verdict

    def reduceGroup(self, verdicts, group, path, creder):
        """ Returns the EdgeVerdict of one Edge-group, reduced over its members

        Parameters:
            verdicts (list): EdgeVerdict of each member, in section order
            group (dict): the Edge-group block, possibly the Edge Section itself
            path (tuple): non-reserved labels locating the group within the Edge
                Section; empty for the Edge Section, which is the top-level group
            creder (Creder): the near (edge-bearing) credential, for diagnostics

        Raises:
            ValidationError: a nested Edge-group with no members. Read as valid it
                would satisfy an enclosing AND, and read as invalid it would refuse a
                section its Issuer wrote deliberately, so it is malformed rather than
                either. An Edge *Section* with no edges is different and ordinary --
                it is the shape of an unchained ACDC -- and is vacuously satisfied.

        """
        op = group['o'] if 'o' in group else self.DefaultMAryOp
        where = f"edge group {'.'.join(path)}" if path else "the edge section"

        if not verdicts:
            if path:
                raise ValidationError(f"Edge-group {'.'.join(path)} of credential "
                                      f"{creder.said} has no members to reduce "
                                      f"under {op}")
            return chaining.valid(f"credential {creder.said} carries no edges")

        if op in chaining.MAryReducers:
            return chaining.reduce(op, verdicts)

        # Recognized but not reduced (NAND, NOR, AVG, WAVG), or not an Operator this
        # verifier knows at all. Either way the group's validity is unknown and no
        # arrival settles it, so it enters the lattice rather than aborting the
        # section: under Kleene reduction an absorbed unknown cannot change a verdict
        # its siblings already decide, which is exactly what the spec's OR row says
        # should happen. Where it *is* outcome-relevant the section reduces to a
        # non-retryable unknown, and .disposeSection refuses without escrow.
        if op in self.MAryOps:
            reason = (f"Unsupported m-ary edge operator {op} on {where} of credential "
                      f"{creder.said}; reducible are {sorted(chaining.MAryReducers)}")
        else:
            reason = (f"Unrecognized m-ary edge operator {op!r} on {where} of "
                      f"credential {creder.said}; expected one of {self.MAryOps}")
        return chaining.unknown(reason, retryable=False,
                                cause=EdgeCause(ValidationError(reason), None, None))

    def evaluateEdge(self, path, node, pins, creder):
        """ Returns the EdgeVerdict of one Edge, on both axes that decide it

        An edge is decided on the unary Operator's relation between the near and far
        nodes, and on the far node itself -- whether it is in hand, whether it
        satisfies every schema pinned on the edge and its enclosing groups, and what
        its registry says about it. Both have to reach the m-ary reduction as one
        value or the Operator does not aggregate what the spec says it aggregates.

        Parameters:
            path (tuple): non-reserved labels locating this Edge within the Edge
                Section
            node (dict): the Edge block, which carries the far node SAID at `n`
            pins (dict): schema pins in force, keyed by Edge-group path
            creder (Creder): the near (edge-bearing) credential

        """
        label = '.'.join(path)  # dotted path so nested edges are locatable
        nodeSaid = node["n"]
        op = node['o'] if 'o' in node else None
        where = f"credential {creder.said} chain {label}({nodeSaid})"

        try:
            state = self.verifyChain(nodeSaid, op, creder.israid, creder.iseaid)
        except (EdgeRefusalError, UnsupportedOperatorError) as ex:
            # .verifyChain knows the far node but not the near credential that
            # carried the edge, so re-raise with the near SAID and edge label to
            # locate it. Preserve the class: an edge that does not hold and one this
            # validator cannot evaluate are different claims, and they take different
            # places in the lattice -- invalid is decided against, unknown is not
            # decided at all, which is what lets a sibling under OR carry the group
            # over an operator this verifier cannot reach.
            reason = f"Failure to verify {where}: {ex}"
            cause = EdgeCause(type(ex)(reason), None, None)
            if isinstance(ex, EdgeRefusalError):
                return chaining.invalid(reason, cause=cause)
            return chaining.unknown(reason, retryable=False, cause=cause)

        if state is None:
            reason = f"Failure to verify {where}"
            return chaining.unknown(reason, retryable=True,
                                    cause=EdgeCause(MissingChainError(reason),
                                                    dict(kin="proof", said=nodeSaid),
                                                    self.escrowMCE))

        # Enforce the edge's declared far-node schema ('s'). Per ACDC (S. Smith,
        # issue #1534) the edge 's' is a schema the far node must *satisfy*, not a
        # SAID that must equal the far node's own schema SAID. The far node already
        # validated against its own schema (it is saved, per verifyChain above), so
        # an edge declaring that same schema needs no further check. When the edge
        # declares a *different* schema, the far node must additionally satisfy it:
        # if it does, the near side is legitimately requiring a backwards-compatible
        # (e.g. upgraded) schema without the far node being reissued; if it does not,
        # the edge schema is not backwards compatible and the far node must be
        # reissued.
        # Every pin in force here, enclosing groups first, then the edge's own.
        # Conjunction, not override: an inherited pin is a floor, so an edge carrying
        # its own `s` must satisfy both and cannot release itself from a constraint
        # its group placed. This is the #1534 rule ("two schema validations must be
        # performed and both must be valid") applied one level out.
        for nodeSchema in pins[path[:-1]] + ((node['s'],) if 's' in node else ()):
            farCreder = self.reger.creds.get(keys=nodeSaid)
            if farCreder.schema != nodeSchema:
                scraw = self.resolver.resolve(nodeSchema)
                if not scraw:  # edge schema not cached yet -- transient
                    reason = (f"edge schema {nodeSchema} for {where} not in cache")
                    return chaining.unknown(
                        reason, retryable=True,
                        cause=EdgeCause(MissingSchemaError(reason),
                                        dict(kin="query",
                                             q=dict(r="schema", said=nodeSchema)),
                                        self.escrowMSE))
                try:
                    Schemer(raw=scraw).verify(farCreder.raw)
                except ValidationError as ex:  # far node fails the edge schema
                    # Decided, not pending. The far node's SAD is fixed under its
                    # SAID and the pin under the near ACDC's, so nothing that arrives
                    # makes one satisfy the other.
                    reason = (f"{where} far node does not satisfy edge schema "
                              f"{nodeSchema}: {ex}")
                    return chaining.invalid(
                        reason, cause=EdgeCause(EdgeRefusalError(reason), None, None))

        dtnow = helping.nowUTC()
        dte = helping.fromIso8601(state.dt)
        if (dtnow - dte) > datetime.timedelta(seconds=self.CredentialExpiry):
            reason = f"Failure to verify {where}: far node state is out of date"
            return chaining.unknown(
                reason, retryable=True,
                cause=EdgeCause(MissingChainError(reason),
                                dict(kin="query", q=dict(r="tels", pre=nodeSaid)),
                                self.escrowMCE))

        if state.et in (Ilks.rev, Ilks.brv):
            reason = f"Failure to verify {where}: far node is revoked"
            return chaining.invalid(
                reason, cause=EdgeCause(RevokedChainError(reason), None, None))

        return chaining.valid(f"Successfully validated {where}")

    def disposeSection(self, verdict, creder, prefixer, seqner, saider):
        """ Acts once on the Edge Section's reduced verdict

        One disposition per ACDC rather than one per failing edge. Which one follows
        from the verdict and, for an unknown, from the retryability that propagated
        with it -- so this reads a bit rather than re-deriving which members were
        outstanding.

        Parameters:
            verdict (EdgeVerdict): the reduced verdict of the whole Edge Section
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix (AID or TEL) of event anchoring credential
            seqner (Seqner): sequence number of event anchoring credential
            saider (Diger): digest of anchoring event for credential

        Raises:
            ValidationError: of the class the deciding member's evidence produced,
                unless the section is valid. An unknown the verifier can still
                resolve escrows first and cues a query for every member it is waiting
                on -- cueing only the first would age the escrow out having asked for
                half of what it waits on. An invalid section, and an unknown no
                arrival can settle, refuse without escrow: parking either promises a
                retry that cannot succeed.

        """
        if verdict.verdict == chaining.Verdicts.valid:
            logger.info("Successfully validated edge section for credential %s: %s",
                        creder.said, verdict.reason)
            return

        causes = [cause for cause in verdict.causes if isinstance(cause, EdgeCause)]

        if verdict.verdict == chaining.Verdicts.unknown:
            # Only the members that can still be resolved carry an escrow and a cue;
            # an unknown no arrival can settle carries neither.
            pending = [cause for cause in causes if cause.escrow is not None]

            if verdict.retryable and pending:
                # One escrow row per table, keyed on the near ACDC's SAID, however
                # many members are outstanding -- but a cue for every one of them, or
                # the entry ages out having asked for only the member that happened
                # to be walked first. Cueing is gated on the escrow being new so an
                # escrow pass that re-runs a credential does not re-send every query.
                escrows = dict.fromkeys(cause.escrow for cause in pending)
                fresh = [escrow(creder, prefixer, seqner, saider)
                         for escrow in escrows]
                if any(fresh):
                    for cause in pending:
                        if cause.cue:
                            self.cues.append(cause.cue)
                raise pending[0].exc

            # Not retryable, so name a member that can never be settled rather than
            # one that is merely outstanding. Raising the outstanding one would
            # report a transient error for a section that will never verify, and the
            # escrow tables .processEscrows keys on those classes would collect an
            # entry this branch has deliberately refused to write.
            settled = [cause for cause in causes if cause.escrow is None]
            if settled:
                raise settled[0].exc

        if causes:
            raise causes[0].exc

        raise ValidationError(f"Failure to verify credential {creder.said} edge "
                              f"section: {verdict.reason}")

    def verifyGroup(self, group, path, creder):
        """ Verifies an Edge-group's m-ary Operator is well-formed

        Only the shape, not the token. Whether this verifier can *reduce* the named
        Operator is a question about the group's validity, which .reduceGroup answers
        with a verdict; whether the group named an Operator at all is a question
        about whether the ACDC is well-formed, which has no answer in the lattice and
        so is refused here, before any reduction runs.

        Parameters:
            group (dict): the Edge-group block, possibly the Edge Section itself
            path (tuple): non-reserved labels locating the group within the Edge
                Section; empty for the Edge Section, which is the top-level group
            creder (Creder): the near (edge-bearing) credential, for diagnostics

        Raises:
            ValidationError: the group's `o` is not a single Operator token.
                Deliberately not a MissingChainError: the section is fully in hand
                and no arrival makes a malformed section well-formed, so escrowing
                would promise a retry that can never succeed.

        """
        # An absent `o` is not "no operator": the spec assigns it a value, and that
        # value goes through the same check as an explicit one so the default can
        # never drift into an unreducible token unnoticed.
        op = group['o'] if 'o' in group else self.DefaultMAryOp
        where = f"edge group {'.'.join(path)}" if path else "the edge section"

        # Unlike an Edge's unary `o`, an Edge-group's `o` is a single aggregating
        # Operator over the group's members -- the spec defines no list form for it.
        if not isinstance(op, str):
            raise ValidationError(f"Unrecognized m-ary edge operator {op!r} on "
                                  f"{where} of credential {creder.said}; expected "
                                  f"one of {self.MAryOps}")

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
            issuer (str) qb64 AID of the issuer of the near (edge-bearing) ACDC
            issuee (str|None): qb64 AID of the issuee of the near (edge-bearing) ACDC,
                required by the identity operators (E1E). None when the near ACDC is
                untargeted.

        Returns:
            Serder: transaction event state notification message, or None when the
                edge cannot be decided yet because evidence is missing -- the far
                node is not saved, its issuee indexes no saved credential, its
                registry is not in .tevers, or its TEL carries no state for the far
                SAID. None is the caller's signal to escrow and retry.

        Raises:
            EdgeRefusalError: the operator's constraint is decided against evidence
                in hand and fails. Both sides of every comparison here are fixed in
                SADs already held, so retrying cannot change the answer and the
                caller must not escrow.
            UnsupportedOperatorError: the operator is recognized but unimplemented,
                so the edge's validity is unknown rather than false.

        """
        # `o` is either a single unary operator or a list of them. An absent or empty
        # operator takes the default rule below; a token outside .UnaryOps does not.
        # Dropping an unrecognized token and defaulting would validate the edge under a
        # substituted operator, and since every unary operator exists to narrow what
        # satisfies an edge, the substitute is always the more permissive rule -- a
        # silent relaxation of what the Issuer wrote. The ACDC unary table
        # (spec-body.md:1190-1195) says nothing about a fifth token, so failing closed
        # here is keripy's choice where the spec is silent.
        #
        # Checked before the far-node lookup on purpose: an operator this validator
        # cannot evaluate stays that way however much evidence arrives, so reporting a
        # missing far node first would promise a retry the operator forbids.
        # ~3qah  reverses #1552's skip; needs S. Smith's buy-in via ACDC #201
        ops = op if isinstance(op, (list, tuple)) else ([] if op is None else [op])
        unknown = [cand for cand in ops if cand not in self.UnaryOps]
        if unknown:
            raise UnsupportedOperatorError(f"Unrecognized edge operator(s) {unknown} on "
                                           f"edge to node {nodeSaid}; recognized are "
                                           f"{list(self.UnaryOps)}")

        said = self.reger.saved.get(keys=nodeSaid)
        if said is None:
            return None

        creder = self.reger.creds.get(keys=nodeSaid)  # far (node) credential

        # Latest-wins applies only "among the conflicting Operators" (ACDC spec, Edge
        # Section > Edge > Operator, `o` field), so the list is resolved in two parts:
        # the delegative operators constrain the same thing (the near issuer relative
        # to the far issuee) and therefore conflict, so the latest of those wins; E1E
        # constrains the near issuee instead, so it does not conflict with them and
        # composes (AND) rather than overriding or being overridden.
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
            raise UnsupportedOperatorError(f"Unsupported edge operator NOT on edge to node "
                                  f"{nodeSaid}; NOT validation is not implemented")

        if op == 'DI2I':
            raise UnsupportedOperatorError(f"Unsupported edge operator DI2I on edge to node "
                                  f"{nodeSaid}; DI2I validation is not implemented")

        if 'E1E' in ops:
            # Identity relation (discussion #1515): the issuee AID of the near ACDC
            # (the one carrying this edge) MUST equal the issuee AID of the far node.
            # Unlike the delegative I2I, this says nothing about the issuer, so the
            # common SEDI case -- both credentials issued by a third party to the same
            # subject, issuer != issuee -- is valid (and is exactly what I2I rejects).
            # Resolve the far issuee via .iseaid so an aggregate node (A[1].i) works too.
            # A mismatch is decided, not pending: both issuees are fixed in SADs already
            # in hand, so no later arrival makes them equal. Refuse rather than return
            # None, which the caller would escrow and retry forever.
            farIssuee = creder.iseaid
            if farIssuee is None or issuee is None or issuee != farIssuee:
                raise EdgeRefusalError(f"E1E edge to node {nodeSaid} requires equal "
                                       f"issuees; near issuee {issuee} != far issuee "
                                       f"{farIssuee}")

        if op is not None and op != 'NI2I':
            # Resolve the far node's issuee via .iseaid so an aggregate ('acg') far
            # node (issuee at .sad["A"][1]["i"]) resolves identically to an
            # attributive one (.attrib["i"]). None means an untargeted far node,
            # which cannot satisfy a targeted (I2I/DI2I) edge -- and cannot become
            # targeted later, since the issuee is part of the SAD under its SAID.
            farIssuee = creder.iseaid
            if farIssuee is None:
                raise EdgeRefusalError(f"{op} edge to node {nodeSaid} requires a "
                                       f"targeted far node, which has no issuee")

            # Transient, unlike the two refusals around it: .subjs indexes the
            # credentials this validator happens to have saved for that issuee, so a
            # miss means the evidence has not arrived rather than that the edge fails.
            iss = self.reger.subjs.get(keys=farIssuee)
            if iss is None:
                return None

            if op == 'I2I' and issuer != farIssuee:
                raise EdgeRefusalError(f"I2I edge to node {nodeSaid} requires the near "
                                       f"issuer to be the far issuee; issuer {issuer} "
                                       f"!= far issuee {farIssuee}")

        if creder.regid not in self.tevers:
            return None

        tever = self.tevers[creder.regid]

        state = tever.vcState(nodeSaid)
        if state is None:
            return None

        return state
