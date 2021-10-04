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
from ..vc import proving
from ..vdr import eventing
from ..vdr.eventing import VcStates
from ..vdr.viring import Registry

logger = help.ogler.getLogger()


class Verifier:
    """
    Verifier class accepts and validates TEL events.

    """
    TimeoutPSE = 3600  # seconds to timeout partially signed credential escrow
    TimeoutMRE = 3600  # seconds to timeout missing registry escrows
    TimeoutMRI = 3600  # seconds to timeout missing issuer escrows
    TimeoutBCE = 3600  # seconds to timeout missing issuer escrows

    CredentialExpiry = 3600

    def __init__(self, hab, reger=None, creds=None, cues=None, **kwa):
        """
        Initialize Verifier instance

        Parameters:
            hab is Habitat for this verifier's context
            name is user synonym for this verifier
            reger is Registry database instance
            tevers is dict of Tever instances keys by registry identifier
        """
        self.hab = hab
        self.reger = reger if reger is not None else Registry(name=hab.name, temp=True)
        self.creds = creds if creds is not None else decking.Deck()  # subclass of deque
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque

        self.inited = False
        self.tvy = None
        self.psr = None

        # save init kwy word arg parameters as ._inits in order to later finish
        # init setup elseqhere after databases are opened if not below
        self._inits = kwa

        if self.hab.inited:
            self.setup()

    def setup(self):
        self.tvy = eventing.Tevery(reger=self.reger, db=self.hab.db, regk=None, local=False)
        self.psr = parsing.Parser(framed=True, kvy=self.hab.kvy, tvy=self.tvy)

        self.inited = True

    @property
    def tevers(self):
        """
        Returns .db.tevers
        """
        return self.reger.tevers

    def processMessages(self, creds=None):
        """
        Process message dicts in msgs or if msgs is None in .msgs
        Parameters:
            creds (Deck): each entry is dict that matches call signature of
                .processCredential
        """
        if creds is None:
            creds = self.creds

        while creds:
            self.processCredential(**creds.pull())

    def processCredential(self, creder, prefixer, seqner, diger, sigers):
        """
        Verify the data of the credential against the schema, the SAID of the credential and
        the CESR Proof on the credential and if valid, store the credential

        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential

        """
        regk = creder.status
        vcid = creder.said
        schema = creder.schema
        prov = creder.crd["p"]

        if regk not in self.tevers:  # registry event not found yet
            self.escrowMRE(creder, prefixer, seqner, diger, sigers)
            self.cues.append(dict(kin="query", q=dict(r="logs", pre=creder.issuer, sn=seqner)))
            self.cues.append(dict(kin="telquery", q=dict(r="tels", ri=regk, i=vcid)))
            raise kering.MissingRegistryError("registry identifier {} not in Tevers".format(regk))

        state, lastSeen = self.tevers[regk].vcState(vcid)
        if state is None:  # credential issuance event not found yet
            self.escrowMRE(creder, prefixer, seqner, diger, sigers)
            self.cues.append(dict(kin="query", q=dict(r="logs", pre=creder.issuer, sn=seqner)))
            self.cues.append(dict(kin="telquery", q=dict(r="tels", ri=regk, i=vcid)))
            raise kering.MissingRegistryError("credential identifier {} not in Tevers".format(vcid))

        if state is VcStates.expired:
            self.escrowMRE(creder, prefixer, seqner, diger, sigers)
            self.cues.append(dict(kin="query", q=dict(r="logs", pre=creder.issuer, sn=seqner)))
            self.cues.append(dict(kin="telquery", q=dict(r="tels", ri=regk, i=vcid)))
            raise kering.MissingRegistryError("credential identifier {} is out of date".format(vcid))
        elif state is VcStates.revoked:  # no escrow, credential has been revoked
            raise kering.InvalidCredentialStateError("credential {} in registrying is not in issued state".format(vcid,
                                                                                                                  regk))

        # we don't know about this issuer
        if creder.issuer not in self.hab.kevers:
            self.escrowMIE(creder, prefixer, seqner, diger, sigers)
            self.cues.append(dict(kin="query", q=dict(r="logs", pre=creder.issuer, sn=seqner)))
            raise kering.MissingIssuerError("issuer identifier {} not in Kevers".format(creder.issuer))

        # Verify the credential against the schema
        scraw = scheming.jsonSchemaCache.resolve(schema)
        if not scraw:
            self.escrowMSE(creder, prefixer, seqner, diger, sigers)
            self.cues.append(dict(kin="query", q=dict(r="schema", said=schema)))
            raise kering.MissingSchemaError("schema {} not in cache".format(schema))


        schemer = scheming.Schemer(raw=scraw)
        if not schemer.verify(creder.raw):
            raise kering.FailedSchemaValidationError("Credential {} is not valid against schema {}"
                                                     .format(creder.said, schema))

        # Verify the signatures are valid and that the signature threshold as of the signing event is met
        tholder, verfers = self.hab.verifiage(pre=prefixer.qb64, sn=seqner.sn, dig=diger.qb64)
        _, indices = eventing.verifySigs(creder, sigers, verfers)

        if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
            self.escrowPSC(creder, prefixer, seqner, diger, sigers)
            raise kering.MissingSignatureError("Failure satisfying credential sith = {} on sigs for {}"
                                               " for evt = {}.".format(tholder.sith,
                                                                       [siger.qb64 for siger in sigers],
                                                                       creder.crd))
        for s in prov:
            for label, node in s.items():
                nodeSubject = node["i"]
                nodeSaid = node["d"]
                status = self.verifyChain(label, nodeSubject, nodeSaid)
                if status is None:
                    self.escrowMCE(creder, prefixer, seqner, diger, sigers)
                    self.cues.append(dict(kin="proof", subject=nodeSubject, said=nodeSaid))
                    raise kering.MissingChainError("Failure to verify credential {} chain {}({}) for {}"
                                                   .format(creder.said, label, nodeSaid, nodeSubject))
                elif status == VcStates.expired:
                    self.escrowMCE(creder, prefixer, seqner, diger, sigers)
                    self.cues.append(dict(kin="query", q=dict(r="tels", pre=nodeSaid)))
                    raise kering.MissingChainError("Failure to verify credential {} chain {}({}) for {}"
                                                   .format(creder.said, label, nodeSaid, nodeSubject))
                elif status == VcStates.revoked:
                    raise kering.RevokedChainError("Failure to verify credential {} chain {}({}) for {}"
                                                   .format(creder.said, label, nodeSaid, nodeSubject))
                else:  # VcStatus == VcStates.Issued
                    logger.info("Successfully validated credential chain {} for credential {}"
                                .format(label, creder.said))


        self.saveCredential(creder, prefixer, seqner, diger, sigers)
        proof = proving.buildProof(prefixer, seqner, diger, sigers)
        self.cues.append(dict(kin="saved", creder=creder, proof=proof))

    def escrowPSC(self, creder, prefixer, seqner, diger, sigers):
        """
        Credential Partial Signature Escrow


        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential

        """
        key = creder.saider.qb64b

        self._persist(creder, prefixer, seqner, diger, sigers)
        self.reger.pse.pin(keys=key, val=coring.Dater())

    def escrowMRE(self, creder, prefixer, seqner, diger, sigers):
        """
        Missing Registry Escrow


        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential

        """
        key = creder.saider.qb64b

        self._persist(creder, prefixer, seqner, diger, sigers)
        self.reger.mre.pin(keys=key, val=coring.Dater())

    def escrowMIE(self, creder, prefixer, seqner, diger, sigers):
        """
        Missing Issuer Escrow


        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential

        """
        key = creder.saider.qb64b

        self._persist(creder, prefixer, seqner, diger, sigers)
        self.reger.mie.pin(keys=key, val=coring.Dater())

    def escrowMCE(self, creder, prefixer, seqner, diger, sigers):
        """
        Missing Issuer Escrow


        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential

        """
        key = creder.saider.qb64b

        self._persist(creder, prefixer, seqner, diger, sigers)
        self.reger.mce.pin(keys=key, val=coring.Dater())

    def escrowMSE(self, creder, prefixer, seqner, diger, sigers):
        """
        Missing Credential Schema Escrow


        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential

        """
        key = creder.saider.qb64b

        self._persist(creder, prefixer, seqner, diger, sigers)
        self.reger.mse.pin(keys=key, val=coring.Dater())

    def processEscrows(self):
        """
        Process all escrows once each

        """

        self._processEscrow(self.reger.mce, self.TimeoutMRI, kering.MissingChainError)
        self._processEscrow(self.reger.mse, self.TimeoutMRI, kering.MissingSchemaError)
        self._processEscrow(self.reger.pse, self.TimeoutPSE, kering.MissingSignatureError)
        self._processEscrow(self.reger.mie, self.TimeoutMRI, kering.MissingIssuerError)
        self._processEscrow(self.reger.mre, self.TimeoutMRE, kering.MissingRegistryError)

    def _processEscrow(self, db, timeout, etype: Type[Exception]):
        """
        Generic credential escrow processing

        Parameters:
            db:
            timeout:
            etype:

        """
        for (said,), dater in db.getItemIter():
            creder, prefixer, seqner, diger, sigers = self._read(said)

            try:

                dtnow = helping.nowUTC()
                dte = helping.fromIso8601(dater.dts)
                if (dtnow - dte) > datetime.timedelta(seconds=timeout):
                    # escrow stale so raise ValidationError which unescrows below
                    logger.info("Verifier unescrow error: Stale event escrow "
                                " at said = %s\n", bytes(said))

                    raise kering.ValidationError("Stale event escrow "
                                                 "at said = {}.".format(bytes(said)))

                self.processCredential(creder, prefixer, seqner, diger, sigers)

            except etype as ex:
                print(ex)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Verifiery unescrow failed: %s\n", ex.args[0])
                else:
                    logger.error("Verifier unescrow failed: %s\n", ex.args[0])
            except Exception as ex:  # log diagnostics errors etc
                print(ex)
                # error other than missing sigs so remove from PA escrow
                db.rem(said)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Verifier unescrowed: %s\n", ex.args[0])
                else:
                    logger.error("Verifier unescrowed: %s\n", ex.args[0])
            else:
                db.rem(said)
                logger.info("Verifier unescrow succeeded in valid group op: "
                            "creder=\n%s\n", creder.pretty())

    def saveCredential(self, creder, prefixer, seqner, diger, sigers):
        """
        Write the credential and associated indicies to the database

        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential
        """
        self._persist(creder, prefixer, seqner, diger, sigers)

        schema = creder.schema.encode("utf-8")
        issuer = creder.issuer.encode("utf-8")
        subject = creder.subject["i"].encode("utf-8")

        # Look up indicies
        saider = creder.saider
        self.reger.issus.add(keys=issuer, val=saider)
        self.reger.subjs.add(keys=subject, val=saider)
        self.reger.schms.add(keys=schema, val=saider)

    def _persist(self, creder, prefixer, seqner, diger, sigers):
        """
        Save the base credential and seals (est evt+sigs quad) with no indices.

        Parameters:
            creder (Credentialer) that contains the credential to process
            prefixer (Prefixer) Identifier of the issuer of the credential
            seqner (Seqner) is the sequence number of the event used to sign the credential
            diger (Diger) is the digest of the event used to sign the credential
            sigers (list) are the cryptographic signatures on the credential
        """
        key = creder.saider.qb64b
        self.reger.creds.put(keys=key, val=creder)

        # Signer KEL Location and signatures
        vals = [(prefixer, seqner, diger, siger) for siger in sigers]
        self.reger.seals.put(keys=key, vals=vals)

    def _read(self, said):
        """
        Load base credential and seals(est evt+sigs quad) from database.

        Parameters:
            said(str or bytes): qb64 SAID of credential

        """

        creder = self.reger.creds.get(keys=said)

        # TODO:  de-dupe the seals here and extract the signatures
        seals = self.reger.seals.get(keys=said)
        prefixer = None
        seqner = None
        diger = None
        sigers = []
        for seal in seals:
            (prefixer, seqner, diger, siger) = seal
            sigers.append(siger)

        return creder, prefixer, seqner, diger, sigers

    def query(self, regk, vcid, res, dt=None, dta=None, dtb=None):
        """
        Returns query message for querying for a single element of type res
        """
        kever = self.hab.kever
        serder = eventing.query(regk=regk, vcid=vcid, res=res, dt=dt, dta=dta, dtb=dtb)

        sigers = self.hab.mgr.sign(ser=serder.raw, verfers=kever.verfers)
        msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted

        msg.extend(coring.Counter(coring.CtrDex.TransLastIdxSigGroups, count=1).qb64b)
        msg.extend(self.hab.pre.encode("utf-8"))

        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        return msg

    def verifyChain(self, label, nodeSubject, nodeSaid):
        """
        Verifies the node credential at the end of an edge

        Returns: None if the credential is not found
                 Expired if the state is issued and the date on the TEL event has expired
                 Issued if the credential has been saved and issued
                 Revoked if the credential has been revoked.

        Parameters:
            label (str): edge label
            nodeSubject(str): qb64 of node credential subject
            nodeSaid: (str) qb64 SAID of node credential

        """
        creder = self.reger.creds.get(keys=nodeSaid)
        if creder is None:
            return None

        iss = self.reger.subjs.get(keys=nodeSubject)
        if iss is None:
            return None

        if creder.status not in self.tevers:
            return None

        tever = self.tevers[creder.status]

        status, lastSeen = tever.vcState(nodeSaid)
        if status is None:
            return None

        dtnow = helping.nowUTC()
        dte = helping.fromIso8601(lastSeen.dts)
        if (dtnow - dte) > datetime.timedelta(seconds=self.CredentialExpiry):
            return VcStates.Expired

        return status
