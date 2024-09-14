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

    def __init__(self, db, subkey, timeout=3600):
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
        self.escrowdb = subing.CesrIoSetSuber(db=self.db, subkey=subkey + '-nes', klas=coring.Saider)

        # transaction state SAID database for successfully saved transaction state notices
        # maps key=(prefix, aid) to val=said of transaction state
        self.saiderdb = subing.CesrSuber(db=self.db, subkey=subkey + '-nas.', klas=coring.Saider)

    def current(self, keys):
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
        for (typ, pre, aid), saider in self.escrowdb.getItemIter(keys=(typ, '')):
            try:
                tsgs = eventing.fetchTsgs(db=self.tigerdb, saider=saider)

                keys = (saider.qb64,)
                dater = self.daterdb.get(keys=keys)
                serder = self.serderdb.get(keys=keys)
                vcigars = self.cigardb.get(keys=keys)

                try:
                    if not (dater and serder and (tsgs or vcigars)):
                        raise ValueError(f"Missing escrow artifacts at said={saider.qb64}"
                                         f"for pre={pre}.")

                    cigars = []
                    if vcigars:
                        for (verfer, cigar) in vcigars:
                            cigar.verfer = verfer
                            cigars.append(cigar)

                    # do date math for stale escrow
                    if ((helping.nowUTC() - dater.datetime) >
                            datetime.timedelta(seconds=self.timeout)):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale txn state escrow "
                                    " at pre = %s", pre)

                        raise kering.ValidationError(f"Stale txn state escrow at pre = {pre}.")

                    processReply(serder=serder, saider=saider, route=serder.ked["r"],
                                 cigars=cigars, tsgs=tsgs, aid=aid)

                except extype as ex:
                    # still waiting on missing prior event to validate
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow attempt failed: %s", ex.args[0])

                except Exception as ex:  # other error so remove from reply escrow
                    self.escrowdb.rem(keys=(typ, pre, aid), val=saider)   # remove escrow
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed due to error: %s", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed due to error: %s", ex.args[0])

                else:  # unescrow succeded
                    self.escrowdb.rem(keys=(typ, pre, aid), val=saider)  # remove escrow
                    logger.info("Kevery unescrow succeeded for txn state=%s",
                                serder.said)
                    logger.debug(f"event=\n{serder.pretty()}\n")

            except Exception as ex:  # log diagnostics errors etc
                self.escrowdb.rem(keys=(typ, pre, aid), val=saider)  # remove escrow
                self.removeState(saider)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery unescrowed due to error: %s", ex.args[0])
                else:
                    logger.error("Kevery unescrowed due to error: %s", ex.args[0])

    def escrowStateNotice(self, *, typ, pre, aid, serder, saider, dater, cigars=None, tsgs=None):
        """
        Escrow reply by route

        Parameters:
            typ (str): escrow type
            pre (str): identifier of key state
            aid (str): identifier of authorizer of key state
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
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

        keys = (saider.qb64,)
        self.daterdb.put(keys=keys, val=dater)  # first one idempotent
        self.serderdb.put(keys=keys, val=serder)  # first one idempotent

        for prefixer, seqner, diger, sigers in tsgs:  # iterate over each tsg
            quadkeys = (saider.qb64, prefixer.qb64, f"{seqner.sn:032x}", diger.qb64)
            self.tigerdb.put(keys=quadkeys, vals=sigers)
        for cigar in cigars:  # process each couple to verify sig and write to db
            self.cigardb.put(keys=keys, vals=[(cigar.verfer, cigar)])

        return self.escrowdb.put(keys=(typ, pre, aid), vals=[saider])  # does not overwrite

    def updateReply(self, aid, serder, saider, dater):
        """
        Update Reply SAD in database given by by serder and associated databases
        for attached cig couple or sig quadruple.
        Overwrites val at key if already exists.

        Parameters:
            aid (str): identifier of key state
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
        """
        keys = (saider.qb64,)

        # Add source of ksn to the key for DATEs too...  (source AID, ksn AID)
        self.daterdb.put(keys=keys, val=dater)  # first one idempotent
        self.serderdb.pin(keys=keys, val=serder)  # first one idempotent
        # Add source of ksn to the key...  (source AID, ksn AID)
        self.saiderdb.pin(keys=(serder.sad["a"]["i"], aid), val=saider)  # overwrite

    def removeState(self, saider):
        if saider:
            keys = (saider.qb64,)

            self.tigerdb.trim(keys=(saider.qb64, ""))  # remove whole branch
            self.cigardb.rem(keys=keys)
            self.serderdb.rem(keys=keys)
            self.daterdb.rem(keys=keys)
