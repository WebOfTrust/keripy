# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.verifying module

VC verifier support
"""
import datetime
import logging
from typing import Type

from hio.help import decking

from .. import help, kering
from ..core import parsing, coring, scheming
from ..help import helping
from ..vdr import eventing
from ..vdr.viring import Reger

logger = help.ogler.getLogger()


class Verifier:
    """
    Verifier class accepts and validates TEL events.

    """
    TimeoutPSE = 3600  # seconds to timeout partially signed credential escrow
    TimeoutMRE = 3600  # seconds to timeout missing registry escrows
    TimeoutMRI = 3600  # seconds to timeout missing issuer escrows
    TimeoutBCE = 3600  # seconds to timeout missing issuer escrows

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
        self.tvy = eventing.Tevery(reger=self.reger, db=self.hby.db, local=False)
        self.psr = parsing.Parser(framed=True, kvy=self.hby.kvy, tvy=self.tvy)
        self.resolver = scheming.CacheResolver(db=self.hby.db)

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

    def processCredential(self, creder, prefixer, seqner, saider):
        """ Credential data and signature(s) verification

        Verify the data of the credential against the schema, the SAID of the credential and
        the CESR Proof on the credential and if valid, store the credential

        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix of source anchoring KEL or TEL event
            seqner (Seqner): sequence number of source anchoring KEL or TEL event
            saider (Saider): SAID of source anchoring KEL or TEL event

        """
        regk = creder.regi
        vcid = creder.said
        schema = creder.schema
        prov = creder.edge if creder.edge is not None else {}

        if regk not in self.tevers:  # registry event not found yet
            if self.escrowMRE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk, i=vcid, issr=creder.issuer)))
            raise kering.MissingRegistryError("registry identifier {} not in Tevers".format(regk))

        state = self.tevers[regk].vcState(vcid)
        if state is None:  # credential issuance event not found yet
            if self.escrowMRE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk, i=vcid)))
            raise kering.MissingRegistryError("credential identifier {} not in Tevers".format(vcid))

        dtnow = helping.nowUTC()
        dte = helping.fromIso8601(state.dt)
        if (dtnow - dte) > datetime.timedelta(seconds=self.CredentialExpiry):
            if self.escrowMRE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk, i=vcid)))
            raise kering.MissingRegistryError("credential identifier {} is out of date".format(vcid))
        elif state.et in (coring.Ilks.rev, coring.Ilks.brv):  # no escrow, credential has been revoked
            logger.error("credential {} in registrying is not in issued state".format(vcid, regk))
            # Log this and continue instead of the previous exception so we save a revoked credential.
            # raise kering.InvalidCredentialStateError("..."))

        # Verify the credential against the schema
        scraw = self.resolver.resolve(schema)
        if not scraw:
            if self.escrowMSE(creder, prefixer, seqner, saider):
                self.cues.append(dict(kin="query", q=dict(r="schema", said=schema)))
            raise kering.MissingSchemaError("schema {} not in cache".format(schema))

        schemer = scheming.Schemer(raw=scraw)
        try:
            schemer.verify(creder.raw)
        except kering.ValidationError as ex:
            print("Credential {} is not valid against schema {}: {}"
                  .format(creder.said, schema, ex))
            raise kering.FailedSchemaValidationError("Credential {} is not valid against schema {}: {}"
                                                     .format(creder.said, schema, ex))

        if isinstance(prov, list):
            edges = prov
        elif isinstance(prov, dict):
            edges = [prov]
        else:
            print(f"Invalid type for edges: {prov}")
            raise kering.ValidationError(f"invalid type for edges: {prov}")

        for edge in edges:
            for label, node in edge.items():
                if label in ('d', 'o'):  # SAID or Operator of this edge block
                    continue
                nodeSaid = node["n"]
                op = node['o'] if 'o' in node else None
                state = self.verifyChain(nodeSaid, op, creder.issuer)
                if state is None:
                    self.escrowMCE(creder, prefixer, seqner, saider)
                    self.cues.append(dict(kin="proof",  said=nodeSaid))
                    raise kering.MissingChainError("Failure to verify credential {} chain {}({})"
                                                   .format(creder.said, label, nodeSaid))

                dtnow = helping.nowUTC()
                dte = helping.fromIso8601(state.dt)
                if (dtnow - dte) > datetime.timedelta(seconds=self.CredentialExpiry):
                    self.escrowMCE(creder, prefixer, seqner, saider)
                    self.cues.append(dict(kin="query", q=dict(r="tels", pre=nodeSaid)))
                    raise kering.MissingChainError("Failure to verify credential {} chain {}({})"
                                                   .format(creder.said, label, nodeSaid))
                elif state.et in (coring.Ilks.rev, coring.Ilks.brv):
                    raise kering.RevokedChainError("Failure to verify credential {} chain {}({})"
                                                   .format(creder.said, label, nodeSaid))
                else:  # VcStatus == VcStates.Issued
                    logger.info("Successfully validated credential chain {} for credential {}"
                                .format(label, creder.said))

        self.saveCredential(creder, prefixer, seqner, saider)
        self.cues.append(dict(kin="saved", creder=creder))

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
        return self.reger.mre.put(keys=key, val=coring.Dater())

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
        return self.reger.mce.put(keys=key, val=coring.Dater())

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
        return self.reger.mse.put(keys=key, val=coring.Dater())

    def processEscrows(self):
        """ Process all escrows once each

        """

        self._processEscrow(self.reger.mce, self.TimeoutMRI, kering.MissingChainError)
        self._processEscrow(self.reger.mse, self.TimeoutMRI, kering.MissingSchemaError)
        self._processEscrow(self.reger.mre, self.TimeoutMRE, kering.MissingRegistryError)

    def _processEscrow(self, db, timeout, etype: Type[Exception]):
        """ Generic credential escrow processing

        Parameters:
            db (LMDBer): escrow database table to process
            timeout (float): escrow specific message timeout
            etype (TypeOf(Exception)): exception class to catch and ignore

        """
        for (said,), dater in db.getItemIter():
            creder, prefixer, seqner, saider = self.reger.cloneCred(said)

            try:

                dtnow = helping.nowUTC()
                dte = helping.fromIso8601(dater.dts)
                if (dtnow - dte) > datetime.timedelta(seconds=timeout):
                    # escrow stale so raise ValidationError which unescrows below
                    logger.info("Verifier unescrow error: Stale event escrow "
                                " at said = %s", said)

                    raise kering.ValidationError("Stale event escrow "
                                                 "at said = {}.".format(said))

                self.processCredential(creder, prefixer, seqner, saider)

            except etype as ex:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Verifiery unescrow failed: %s", ex.args[0])
                else:
                    logger.error("Verifier unescrow failed: %s", ex.args[0])
            except Exception as ex:  # log diagnostics errors etc
                # error other than missing sigs so remove from PA escrow
                db.rem(said)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Verifier unescrowed: %s", ex.args[0])
                else:
                    logger.error("Verifier unescrowed: %s", ex.args[0])
            else:
                db.rem(said)
                logger.info("Verifier unescrow succeeded in valid group op: "
                            "creder=%s", creder.said)
                logger.debug(f"event=\n{creder.pretty()}\n")

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
        issuer = creder.issuer.encode("utf-8")

        # Look up indicies
        saider = coring.Saider(qb64=creder.said)
        self.reger.saved.pin(keys=saider.qb64b, val=saider)
        self.reger.issus.add(keys=issuer, val=saider)
        self.reger.schms.add(keys=schema, val=saider)

        if not isinstance(creder.attrib, str) and 'i' in creder.attrib:
            subject = creder.attrib["i"].encode("utf-8")
            self.reger.subjs.add(keys=subject, val=saider)

    def query(self, pre, regk, vcid, *, dt=None, dta=None, dtb=None, **kwa):
        """ Returns query message for querying registry
        """

        serder = eventing.query(regk=regk, vcid=vcid, dt=dt, dta=dta,
                                dtb=dtb, **kwa)
        hab = self.hby.habs[pre]
        return hab.endorse(serder, last=True)

    def verifyChain(self, nodeSaid, op, issuer):
        """ Verifies the node credential at the end of an edge

        Parameters:
            nodeSaid: (str): qb64 SAID of node credential
            op(str): edge operator
            issuer (str) qb64 AID of issuer

        Returns:
            Serder: transaction event state notification message

        """
        said = self.reger.saved.get(keys=nodeSaid)
        if said is None:
            return None

        creder = self.reger.creds.get(keys=nodeSaid)

        if op not in ['I2I', 'DI2I', 'NI2I']:
            op = 'I2I' if 'i' in creder.attrib else 'NI2I'

        if op != 'NI2I':
            if 'i' not in creder.attrib:
                return None

            iss = self.reger.subjs.get(keys=creder.attrib['i'])
            if iss is None:
                return None

            if op == 'I2I' and issuer != creder.attrib['i']:
                return None

            if op == "DI2I":
                raise NotImplementedError()

        if creder.regi not in self.tevers:
            return None

        tever = self.tevers[creder.regi]

        state = tever.vcState(nodeSaid)
        if state is None:
            return None

        return state
