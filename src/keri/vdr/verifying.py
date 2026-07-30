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

from .eventing import Tevery, Reger, query, walkEdgeSection

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
    # .verifyChain). DI2I and NOT are recognized but unimplemented: they are listed so
    # they fail closed diagnosably instead of being dropped and silently defaulting.
    # E1E is a keripy extension not yet in the spec's normative operator table.
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

    # The subset of .MAryOps whose semantics this verifier implements. AND is the
    # spec's default when an Edge-group's `o` field is absent, and its meaning --
    # the group is valid only if every member is valid -- is exactly the aggregation
    # .processCredential already performs over a flat edge section. The rest are
    # recognized but unimplemented, so they fail closed rather than being silently
    # treated as AND, which would apply a weaker rule than the Issuer specified.
    MAryOpsImplemented = ('AND',)

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

        for edge in edges:
            # An Edge Section is itself an Edge-group and MAY nest further
            # Edge-groups, so walk it rather than assuming every non-reserved label
            # at the top level is a flat edge. Every Edge-group encountered has its
            # m-ary Operator checked; every Edge found, at any depth, is validated.
            # This is the AND aggregation -- the spec default -- and .verifyGroup
            # rejects any group asking for something else.
            for path, node, group in walkEdgeSection(edge):
                if group:
                    self.verifyGroup(node, path, creder)
                    continue

                label = '.'.join(path)  # dotted path so nested edges are locatable
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

    def verifyGroup(self, group, path, creder):
        """ Verifies the m-ary Operator of an Edge-group is one this verifier honors

        Carries none of the aggregation semantics of the operators themselves beyond
        AND: the caller validates every Edge in the section and fails on the first
        bad one, which is AND. This method's job is to confirm the Issuer actually
        asked for AND, so a group asking for something else cannot be quietly
        validated under the wrong rule.

        Parameters:
            group (dict): the Edge-group block, possibly the Edge Section itself
            path (tuple): non-reserved labels locating the group within the Edge
                Section; empty for the Edge Section, which is the top-level group
            creder (Creder): the near (edge-bearing) credential, for diagnostics

        Raises:
            ValidationError: the group's `o` is not a recognized m-ary Operator, or
                is recognized but unimplemented. Deliberately not a MissingChainError
                in either case: the section is fully in hand and no amount of
                retrying will make an unsupported operator supported, so escrowing
                would promise a retry that can never succeed. This matches the
                treatment .verifyChain gives NOT and DI2I.

        """
        # An absent `o` is not "no operator": the spec assigns it a value, and that
        # value goes through the same checks as an explicit one so the default can
        # never drift out of .MAryOpsImplemented unnoticed.
        op = group['o'] if 'o' in group else self.DefaultMAryOp
        where = f"edge group {'.'.join(path)}" if path else "the edge section"

        # Unlike an Edge's unary `o`, an Edge-group's `o` is a single aggregating
        # Operator over the group's members -- the spec defines no list form for it.
        if not isinstance(op, str) or op not in self.MAryOps:
            raise ValidationError(f"Unrecognized m-ary edge operator {op!r} on "
                                  f"{where} of credential {creder.said}; expected "
                                  f"one of {self.MAryOps}")

        if op not in self.MAryOpsImplemented:
            raise ValidationError(f"Unsupported m-ary edge operator {op} on {where} "
                                  f"of credential {creder.said}; only "
                                  f"{self.MAryOpsImplemented} is implemented")

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
            Serder: transaction event state notification message

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

        if op == 'DI2I':
            raise ValidationError(f"Unsupported edge operator DI2I on edge to node "
                                  f"{nodeSaid}; DI2I validation is not implemented")

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

        if op is not None and op != 'NI2I':
            # Resolve the far node's issuee via .iseaid so an aggregate ('acg') far
            # node (issuee at .sad["A"][1]["i"]) resolves identically to an
            # attributive one (.attrib["i"]). None means an untargeted far node,
            # which cannot satisfy a targeted (I2I/DI2I) edge.
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
