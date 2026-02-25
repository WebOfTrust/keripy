# -*- encoding: utf-8 -*-
"""
keri.core.escrowing module

"""
import datetime
import logging
from typing import Type


from keri import kering
from keri import help
from keri.help import helping

from keri.core import coring, eventing, indexing
from keri.db import subing


logger = help.ogler.getLogger()


class Broker:
    """
    Collection of databases for transaction state notices (TSNs) and handling TSN escrows.
    """

    def __init__(self, db, subkey, timeout=3600):
        """
        Initialize Broker with databases for transaction state notices and escrows.
        Parameters:
            db (Reger): TEL event database to make sub databases under
            subkey (str): parent LMDB subkey path to use for all sub databases
            timeout (int): timeout in seconds for escrows, default is 3600 seconds (1 hour)

        Attributes:
            db (Reger): TEL event database to make sub databases under
            timeout (int): timeout in seconds for escrows, default is 3600 seconds (1 hour)
            daterdb (CesrSuber): database for datetime stamps by ksn SAID
            serderdb (SerderSuber): database for reply messages by ksn SAID
            tigerdb (CesrIoSetSuber): database for indexed signatures by ksn quadruple
                Key schema: (said, pre, sn, dig)
            cigardb (CatCesrIoSetSuber): database for non-indexed signatures by ksn SAID
            escrowdb (CesrIoSetSuber): database for escrows by route by (typ, pre, aid) tuple
            saiderdb (CesrSuber): database for transaction state SAIDs by (pre, aid) tuple
        """
        self.db = db
        self.timeout = timeout

        # State support datetime stamps and signatures indexed and not-indexed
        # all ksn  kdts (key state datetime serializations) maps said to date-time
        self.daterdb = subing.CesrSuber(db=self.db, subkey=subkey + '-dts.', klas=coring.Dater)

        # all reply messages that holdkey state messages.
        # Maps replay messages that hold key state said to serialization. ksns are
        # versioned sads ( with version string) so use Serder to deserialize and
        # use  .kdts, .ksgs, and .kcgs for datetimes and signatures
        self.serderdb = subing.SerderSuber(db=self.db, subkey=subkey + '-sns.')

        # RegStateRecords used as basis for registry state notices in replies
        #self.rsrdb = koming.Komer(db=self.db,
                                   #schema=viring.RegStateRecord,
                                   #subkey=subkey + '-sns.')

        # all key state ksgs (ksn indexed signature serializations) maps ksn quadkeys
        # given by quadruple (saider.qb64, subkeyer.qb64, seqner.q64, diger.qb64)
        #  of reply and trans signer's key state est evt to val Siger for each
        # signature.
        self.tigerdb = subing.CesrIoSetSuber(db=self.db, subkey=subkey + '-sgs.', klas=indexing.Siger)

        # all key state kcgs  (ksn non-indexed signature serializations) maps ksn SAID
        # to couple (Verfer, Cigar) of nontrans signer of signature in Cigar
        # nontrans qb64 of subkeyer is same as Verfer
        self.cigardb = subing.CatCesrIoSetSuber(db=self.db, subkey=subkey + '-cgs.',
                                                klas=(coring.Verfer, coring.Cigar))

        # all key state escrows indices of partially signed ksn messages. Maps
        # route in reply to single (Saider,)  of escrowed ksn.
        # Routes such as /ksn/{aid} or /tsn/registry/{aid}
        self.escrowdb = subing.CesrIoSetSuber(db=self.db, subkey=subkey + '-nes', klas=coring.Diger)

        # transaction state SAID database for successfully saved transaction state notices
        # maps key=(prefix, aid) to val=said of transaction state
        self.saiderdb = subing.CesrSuber(db=self.db, subkey=subkey + '-nas.', klas=coring.Diger)

    def current(self, keys):
        """
        Get successfully saved TSNs by keys.

        Parameters:
            (str, str): keys tuple of (prefix, aid) where prefix is the registry identifier and pre is the issuer

        Returns:
            data (str | None):  UTF-8 encoded string of the SAid of a TSN or None if not found.
        """
        return self.saiderdb.get(keys=keys)

    def processEscrowState(self, typ, processReply, extype: Type[Exception]):
        """ Process escrows for reply messages

        Process escrows for reply messages. Escrows are keyed by reply pre
        and val is reply said

        triple (prefixer, seqner, diger)
        quadruple (prefixer, seqner, diger, siger)

        Parameters:
            typ (str): escrow type
            processReply (func): function to call to process each message taken out of escrow
            extype (Type[Exception]): the expected exception type if the message should remain in escrow

        """
        for (typ, pre, aid), diger in self.escrowdb.getItemIter(keys=(typ, '')):
            try:
                tsgs = eventing.fetchTsgs(db=self.tigerdb, saider=diger)

                keys = (diger.qb64,)
                dater = self.daterdb.get(keys=keys)
                serder = self.serderdb.get(keys=keys)
                vcigars = self.cigardb.get(keys=keys)

                try:
                    if not (dater and serder and (tsgs or vcigars)):
                        msg = f"Missing escrow artifacts at said={diger.qb64} for pre={pre}."
                        logger.info("Broker %s: unescrow error: %s", typ, msg)
                        raise ValueError(msg)

                    cigars = []
                    if vcigars:
                        for (verfer, cigar) in vcigars:
                            cigar.verfer = verfer
                            cigars.append(cigar)

                    # do date math for stale escrow
                    if ((helping.nowUTC() - dater.datetime) >
                            datetime.timedelta(seconds=self.timeout)):
                        # escrow stale so raise ValidationError which unescrows below
                        msg = f"Escrow unescrow error: Stale txn state escrow at pre = {pre}"
                        logger.trace("Broker %s: %s", typ, msg)
                        raise kering.ValidationError(msg)

                    processReply(serder=serder, saider=diger, route=serder.ked["r"],
                                 cigars=cigars, tsgs=tsgs, aid=aid)

                except extype as ex:
                    # still waiting on missing prior event to validate
                    if logger.isEnabledFor(logging.TRACE):
                        logger.trace("Broker %s: unescrow attempt failed: %s\n", typ, ex.args[0])
                        logger.exception("Broker %s: unescrow attempt failed: %s", typ, ex.args[0])

                except Exception as ex:  # other error so remove from reply escrow
                    self.escrowdb.rem(keys=(typ, pre, aid), val=diger)   # remove escrow
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Broker %s: unescrowed due to error: %s", typ, ex.args[0])
                    else:
                        logger.error("Broker  %s: unescrowed due to error: %s", typ, ex.args[0])

                else:  # unescrow succeded
                    self.escrowdb.rem(keys=(typ, pre, aid), val=diger)  # remove escrow
                    logger.info("Broker %s: unescrow succeeded for txn state=%s",
                                typ, serder.said)
                    logger.debug("TXN State Body=\n%s\n", serder.pretty())

            except Exception as ex:  # log diagnostics errors etc
                self.escrowdb.rem(keys=(typ, pre, aid), val=diger)  # remove escrow
                self.removeState(diger)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Broker %s: unescrowed due to error: %s", typ, ex.args[0])
                else:
                    logger.error("Broker %s: unescrowed due to error: %s", typ, ex.args[0])

    def escrowStateNotice(self, *, typ, pre, aid, serder, diger, dater, cigars=None, tsgs=None):
        """
        Escrow reply by route

        Parameters:
            typ (str): escrow type
            pre (str): identifier of key state
            aid (str): identifier of authorizer of key state
            serder (Serder): instance of reply msg (SAD)
            diger (Diger): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
            cigars (list): of Cigar instances that contain nontrans signing couple
                          signature in .raw and public key in .verfer

            tsgs (Iterable): of quadruples of form (prefixer, seqner, diger, siger) where:
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                siger is indexed sig from trans endorser's key from est evt
        """
        cigars = cigars if cigars is not None else []
        tsgs = tsgs if tsgs is not None else []

        keys = (diger.qb64,)
        self.daterdb.put(keys=keys, val=dater)  # first one idempotent
        self.serderdb.put(keys=keys, val=serder)  # first one idempotent

        for prefixer, seqner, tsgdiger, sigers in tsgs:  # iterate over each tsg
            quadkeys = (diger.qb64, prefixer.qb64, f"{seqner.sn:032x}", tsgdiger.qb64)
            self.tigerdb.put(keys=quadkeys, vals=sigers)
        for cigar in cigars:  # process each couple to verify sig and write to db
            self.cigardb.put(keys=keys, vals=[(cigar.verfer, cigar)])

        return self.escrowdb.put(keys=(typ, pre, aid), vals=[diger])  # does not overwrite

    def updateReply(self, aid, serder, diger, dater):
        """
        Update Reply SAD in database given by by serder and associated databases
        for attached cig couple or sig quadruple.
        Overwrites val at key if already exists.

        Parameters:
            aid (str): identifier of key state
            serder (Serder): instance of reply msg (SAD)
            diger (Diger): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
        """
        keys = (diger.qb64,)

        # Add source of ksn to the key for DATEs too...  (source AID, ksn AID)
        self.daterdb.put(keys=keys, val=dater)  # first one idempotent
        self.serderdb.pin(keys=keys, val=serder)  # first one idempotent
        # Add source of ksn to the key...  (source AID, ksn AID)
        self.saiderdb.pin(keys=(serder.sad["a"]["i"], aid), val=diger)  # overwrite

    def removeState(self, diger):
        """Remove all state associated with the given event TSN identified by SAID."""
        if diger:
            keys = (diger.qb64,)

            self.tigerdb.trim(keys=(diger.qb64, ""))  # remove whole branch
            self.cigardb.rem(keys=keys)
            self.serderdb.rem(keys=keys)
            self.daterdb.rem(keys=keys)
