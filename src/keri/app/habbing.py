# -*- encoding: utf-8 -*-
"""
KERI
keri.app.habbing module

"""
import os
import shutil
import json
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Type

import cbor2
import msgpack
import lmdb

from hio.base import doing
from hio.core.serial import serialing

from .. import kering
from .. import help
from ..core.coring import Serder
from ..db.dbing import snKey, dgKey
from ..help import helping
from ..db import dbing, basing, koming
from . import keeping
from ..core import coring, eventing, parsing
from . import apping
from ..kering import UnverifiedProofError, ValidationError

logger = help.ogler.getLogger()


@contextmanager
def openHab(name="test", salt=b'0123456789abcdef', temp=True, **kwa):
    """
    Context manager wrapper for Habitat instance.
    Defaults to temporary database and keeper.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        name(str): name of habitat to create
        salt(bytes): passed to habitat to use for inception
        temp(bool): indicates if this uses temporary databases

    """

    with basing.openDB(name=name, temp=temp) as db, \
            keeping.openKS(name=name, temp=temp) as ks:

        salt = coring.Salter(raw=salt).qb64
        hab = Habitat(name=name, ks=ks, db=db, temp=temp, salt=salt,
                      icount=1, isith=1, ncount=1, nsith=1, **kwa)

        yield hab


class Habitat:
    """
    Habitat class provides direct mode controller's local shared habitat
       e.g. context or environment

    Attributes:
        name (str): alias of controller
        transferable (bool): True means pre is transferable (default)
                    False means pre is nontransferable
        temp (bool): True for testing it modifies tier of salty key
            generation algorithm and persistence of db and ks
        erase (bool): If True erase old private keys, Otherwise not.
        db (basing.Baser): lmdb data base for KEL etc
        ks (keeping.Keeper): lmdb key store
        ridx (int): rotation index (inception == 0) needed for key replay
        kvy (eventing.Kevery): instance for local processing of local msgs
        psr (parsing.Parser):  parses local messages for .kvy
        mgr (keeping.Manager): creates and rotates keys in key store
        pre (str): qb64 prefix of own local controller
        inited (bool): True means fully initialized wrt databases.
                          False means not yet fully initialized


    Properties:
        kever (Kever): instance of key state of local controller
        kevers (dict): of eventing.Kever(s) keyed by qb64 prefix
        iserder (coring.Serder): own inception event
        prefixes (OrderedSet): local prefixes for .db

    """

    def __init__(self, *, name='test', ks=None, db=None,
                 transferable=True, temp=False, erase=True, create=True,
                 **kwa):
        """
        Initialize instance.

        Parameters:
            name is str alias name for local controller of habitat
            ks is keystore lmdb Keeper instance
            db is database lmdb Baser instance
            transferable is Boolean True means pre is transferable (default)
                    False means pre is nontransferable
            temp is Boolean used for persistence of lmdb ks and db directories
                and mode for key generation
            erase is Boolean True means erase private keys once stale
            create is Boolean True means create if identifier doesn't already exist

        Parameters: Passed through via kwa to setup for later init
            seed (str): qb64 private-signing key (seed) for the aeid from which
                the private decryption key may be derived. If aeid stored in
                database is not empty then seed may required to do any key
                management operations. The seed value is memory only and MUST NOT
                be persisted to the database for the manager with which it is used.
                It MUST only be loaded once when the process that runs the Manager
                is initialized. Its presence acts as an authentication, authorization,
                and decryption secret for the Manager and must be stored on
                another device from the device that runs the Manager.
            aeid (str): qb64 of non-transferable identifier prefix for
                authentication and encryption of secrets in keeper. If provided
                aeid (not None) and different from aeid stored in database then
                all secrets are re-encrypted using new aeid. In this case the
                provided prikey must not be empty. A change in aeid should require
                a second authentication mechanism besides the prikey.
            secrecies is list of list of secrets to preload key pairs if any
            code is prefix derivation code
            isith is incepting signing threshold as int, str hex, or list
            icount is incepting key count for number of keys
            nsith is next signing threshold as int, str hex or list
            ncount is next key count for number of next keys
            toad is int or str hex of witness threshold
            wits is list of qb64 prefixes of witnesses
            salt is qb64 salt for creating key pairs
            tier is security tier for generating keys from salt

        """
        self.name = name
        self.transferable = transferable
        self.temp = temp
        self.erase = erase
        self.create = create
        self.db = db if db is not None else basing.Baser(name=name,
                                                         temp=self.temp,
                                                         reopen=True)
        self.ks = ks if ks is not None else keeping.Keeper(name=name,
                                                           temp=self.temp,
                                                           reopen=True)
        self.ridx = 0  # rotation index of latest establishment event
        self.kvy = eventing.Kevery(db=self.db, lax=False, local=True)
        self.psr = parsing.Parser(framed=True, kvy=self.kvy)
        self.mgr = None  # wait to setup until after ks is known to be opened
        self.pre = None  # wait to setup until after db is known to be opened
        self.inited = False

        # save init kwy word arg parameters as ._inits in order to later finish
        # init setup elseqhere after databases are opened if not below
        self._inits = kwa

        if self.db.opened and self.ks.opened:
            self.setup(**self._inits)  # finish setup later


    def setup(self, *, seed=None, aeid=None, secrecies=None, code=coring.MtrDex.Blake3_256,
                 isith=None, icount=1, nsith=None, ncount=None,
                 toad=None, wits=None, algo=None, salt=None, tier=None,):
        """
        Setup habitat. Assumes that both .db and .ks have been opened.
        This allows dependency injection of .db and .ks into habitat instance
        prior to .db and .kx being opened to accomodate asynchronous process
        setup of these resources. Putting the .db and .ks associated
        initialization here enables asynchronous opening .db and .ks after
        Baser and Keeper instances are instantiated. First call to .setup will
        initialize databases (vacuous initialization).

        Parameters:
            seed (str): qb64 private-signing key (seed) for the aeid from which
                the private decryption key may be derived. If aeid stored in
                database is not empty then seed may required to do any key
                management operations. The seed value is memory only and MUST NOT
                be persisted to the database for the manager with which it is used.
                It MUST only be loaded once when the process that runs the Manager
                is initialized. Its presence acts as an authentication, authorization,
                and decryption secret for the Manager and must be stored on
                another device from the device that runs the Manager.
            aeid (str): qb64 of non-transferable identifier prefix for
                authentication and encryption of secrets in keeper. If provided
                aeid (not None) and different from aeid stored in database then
                all secrets are re-encrypted using new aeid. In this case the
                provided prikey must not be empty. A change in aeid should require
                a second authentication mechanism besides the prikey.
            secrecies is list of list of secrets to preload key pairs if any
            code is prefix derivation code
            isith is incepting signing threshold as int, str hex, or list
            icount is incepting key count for number of keys
            nsith is next signing threshold as int, str hex or list
            ncount is next key count for number of next keys
            toad is int or str hex of witness threshold
            wits is list of qb64 prefixes of witnesses
            salt is str for algorithm (randy or salty) for creating key pairs
                default is root algo which defaults to salty
            salt is qb64 salt for creating key pairs
            tier is security tier for generating keys from salt
        """
        if not (self.ks.opened and self.db.opened):
            raise kering.ClosedError("Attempt to setup Habitat with closed "
                                     "database, .ks or .db.")
        if nsith is None:
            nsith = isith
        if ncount is None:
            ncount = icount
        if not self.transferable:
            ncount = 0  # next count
            code = coring.MtrDex.Ed25519N
        pidx = None

        # for persisted Habitats, check the KOM first to see if there is an existing
        # one we can restart from otherwise initialize a new one
        existing = False
        if not self.temp:
            ex = self.db.habs.get(keys=self.name)
            # found existing habitat, otherwise leave __init__ to incept a new one.
            if ex is not None:  # replace params with persisted values from db
                prms = self.ks.prms.get(ex.prefix)
                algo = prms.algo
                salt = prms.salt
                tier = prms.tier
                pidx = prms.pidx
                self.pre = ex.prefix
                existing = True

        if not existing and not self.create:
            raise kering.ConfigurationError("Improper Habitat creating for create False")

        if salt is None:
            salt = coring.Salter(raw=b'0123456789abcdef').qb64

        self.mgr = keeping.Manager(ks=self.ks, seed=seed, aeid=aeid, pidx=pidx,
                                   algo=algo, salt=salt, tier=tier)

        if existing:
            self.reinitialize()
        else:
            if secrecies:
                verferies, digers = self.mgr.ingest(secrecies,
                                                    ncount=ncount,
                                                    stem=self.name,
                                                    transferable=self.transferable,
                                                    temp=self.temp)
                opre = verferies[0][0].qb64  # old pre default needed for .replay
                verfers, digers, cst, nst = self.mgr.replay(pre=opre, ridx=self.ridx)
            else:
                verfers, digers, cst, nst = self.mgr.incept(icount=icount,
                                                            isith=isith,
                                                            ncount=ncount,
                                                            nsith=nsith,
                                                            stem=self.name,
                                                            transferable=self.transferable,
                                                            temp=self.temp)

            opre = verfers[0].qb64  # old pre default move below to new pre from incept
            if digers:
                nxt = coring.Nexter(sith=nst,
                                    digs=[diger.qb64 for diger in digers]).qb64
            else:
                nxt = ""

            serder = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                           sith=cst,
                                           nxt=nxt,
                                           toad=toad,
                                           wits=wits,
                                           code=code)
            self.pre = serder.ked["i"]  # new pre
            self.mgr.move(old=opre, new=self.pre)

            # may want db method that updates .habs. and .prefixes together
            self.db.habs.put(keys=self.name,
                             val=basing.HabitatRecord(prefix=self.pre))
            self.prefixes.add(self.pre)

            # self.kvy = eventing.Kevery(db=self.db, lax=False, local=True)
            # create inception event
            sigers = self.mgr.sign(ser=serder.raw, verfers=verfers)
            self.kvy.processEvent(serder=serder, sigers=sigers)
            # self.psr = parsing.Parser(framed=True, kvy=self.kvy)
            if self.pre not in self.kevers:
                raise kering.ConfigurationError("Improper Habitat inception for "
                                                "pre={}.".format(self.pre))

        self.inited = True

    def reinitialize(self):
        if self.pre is None:
            raise kering.ConfigurationError("Improper Habitat reinitialization missing prefix")

        if self.pre not in self.kevers:
            raise kering.ConfigurationError("Missing Habitat KEL for "
                                            "pre={}.".format(self.pre))

        self.prefixes.add(self.pre)  # ordered set so add is idempotent


        # ridx for replay may be an issue when loading from existing
        self.ridx = self.ks.sits.get(self.pre).new.ridx


    @property
    def iserder(self):
        """
        Return serder of inception event
        """
        if (dig := self.db.getKeLast(eventing.snKey(pre=self.pre, sn=0))) is None:
            raise kering.ConfigurationError("Missing inception event in KEL for "
                                            "Habitat pre={}.".format(self.pre))
        if (raw := self.db.getEvt(eventing.dgKey(pre=self.pre, dig=bytes(dig)))) is None:
            raise kering.ConfigurationError("Missing inception event for "
                                            "Habitat pre={}.".format(self.pre))
        return coring.Serder(raw=bytes(raw))


    @property
    def kevers(self):
        """
        Returns .db.kevers
        """
        return self.db.kevers


    @property
    def kever(self):
        """
        Returns kever for its .pre
        """
        return self.kevers[self.pre]


    @property
    def prefixes(self):
        """
        Returns .db.prefixes
        """
        return self.db.prefixes


    def rotate(self, sith=None, count=None, erase=None,
               toad=None, cuts=None, adds=None, data=None):
        """
        Perform rotation operation. Register rotation in database.
        Returns: bytearrayrotation message with attached signatures.

        Parameters:
            sith is next signing threshold as int or str hex or list of str weights
            count is int next number of signing keys
            erase is Boolean True means erase stale keys
            toad is int or str hex of witness threshold after cuts and adds
            cuts is list of qb64 pre of witnesses to be removed from witness list
            adds is list of qb64 pre of witnesses to be added to witness list
            data is list of dicts of committed data such as seals

        """
        if erase is not None:
            self.erase = erase

        kever = self.kever  # kever.pre == self.pre
        if sith is None:
            sith = kever.tholder.sith  # use previous sith
        if count is None:
            count = len(kever.verfers)  # use previous count

        try:
            verfers, digers, cst, nst = self.mgr.replay(pre=self.pre,
                                                        ridx=self.ridx + 1,
                                                        erase=erase)
        except IndexError:
            verfers, digers, cst, nst = self.mgr.rotate(pre=self.pre,
                                                        count=count,  # old next is new current
                                                        sith=sith,
                                                        temp=self.temp,
                                                        erase=erase)

        if digers:
            nxt = coring.Nexter(sith=nst,
                                digs=[diger.qb64 for diger in digers]).qb64
        else:
            nxt = ""

        # this is wrong sith is not kever.tholder.sith as next was different
        serder = eventing.rotate(pre=kever.prefixer.qb64,
                                 keys=[verfer.qb64 for verfer in verfers],
                                 dig=kever.serder.diger.qb64,
                                 sn=kever.sn + 1,
                                 sith=cst,
                                 nxt=nxt,
                                 toad=toad,
                                 wits=kever.wits,
                                 cuts=cuts,
                                 adds=adds,
                                 data=data)

        sigers = self.mgr.sign(ser=serder.raw, verfers=verfers)
        # update own key event verifier state
        # self.kvy.processEvent(serder=serder, sigers=sigers)
        msg = eventing.messagize(serder, sigers=sigers)
        self.psr.parseOne(ims=bytearray(msg))  # make copy as kvr deletes
        if kever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Habitat rotation for "
                                         "pre={}.".format(self.pre))
        self.ridx += 1  # successful rotate so increment for next time

        return msg


    def interact(self, data=None):
        """
        Perform interaction operation. Register interaction in database.
        Returns: bytearray interaction message with attached signatures.
        """
        kever = self.kever
        serder = eventing.interact(pre=kever.prefixer.qb64,
                                   dig=kever.serder.diger.qb64,
                                   sn=kever.sn + 1,
                                   data=data)

        sigers = self.mgr.sign(ser=serder.raw, verfers=kever.verfers)
        # update own key event verifier state
        # self.kvy.processEvent(serder=serder, sigers=sigers)
        msg = eventing.messagize(serder, sigers=sigers)
        self.psr.parseOne(ims=bytearray(msg))  # make copy as kvy deletes
        if kever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Habitat interaction for "
                                         "pre={}.".format(self.pre))

        return msg


    def query(self, pre, res, dt=None, dta=None, dtb=None, sn=None):
        """
        Returns query message for querying for a single element of type res
        """
        kever = self.kever
        serder = eventing.query(pre=pre, res=res, dt=dt, dta=dta, dtb=dtb, sn=sn)

        sigers = self.mgr.sign(ser=serder.raw, verfers=kever.verfers)
        msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted

        msg.extend(coring.Counter(coring.CtrDex.SignerSealCouples, count=1).qb64b)
        msg.extend(pre.encode("utf-8"))

        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        return msg


    def receipt(self, serder):
        """
        Returns own receipt, rct, message of serder with count code and receipt
        couples (pre+cig)
        Builds msg and then processes it into own db to validate
        """
        ked = serder.ked
        reserder = eventing.receipt(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    dig=serder.dig)

        # sign serder event
        if self.kever.prefixer.transferable:
            seal = eventing.SealEvent(i=self.pre,
                                      s="{:x}".format(self.kever.lastEst.s),
                                      d=self.kever.lastEst.d)
            sigers = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=True)
            msg = eventing.messagize(serder=reserder, sigers=sigers, seal=seal)
        else:
            cigars = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=False)
            msg = eventing.messagize(reserder, cigars=cigars)

        self.psr.parseOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def witness(self, serder):
        """
        Returns own receipt, rct, message of serder with count code and witness
        indexed receipt signatures if key state of serder.pre shows that own pre
        is a current witness of event in serder
        """
        if self.kever.prefixer.transferable:  # not non-transferable prefix
            raise ValueError("Attempt to create witness receipt with"
                             " transferable pre={}.".format(self.pre))
        ked = serder.ked

        if serder.pre not in self.kevers:
            raise ValueError("Attempt by {} to witness event with missing key "
                             "state.".format(self.pre))
        kever = self.kevers[serder.pre]
        if self.pre not in kever.wits:
            raise ValueError("Attempt by {} to witness event of {} when not a "
                             "witness in wits={}.".format(self.pre,
                                                          serder.pre,
                                                          kever.wits))
        index = kever.wits.index(self.pre)

        reserder = eventing.receipt(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    dig=serder.dig)
        # sign serder event
        wigers = self.mgr.sign(ser=serder.raw,
                               pubs=[self.pre],
                               indices=[index])

        msg = eventing.messagize(reserder, wigers=wigers, pipelined=True)
        self.psr.parseOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def sanction(self, serder):
        # Sign and messagize the `exn` message with the current signing keys (should be a Habitat method, what name?)
        sigers = self.mgr.sign(ser=serder.raw, verfers=self.kever.verfers)

        msg = bytearray(serder.raw)
        msg.extend(coring.Counter(coring.CtrDex.SignerSealCouples, count=1).qb64b)
        msg.extend(self.pre.encode("utf-8"))

        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        return msg


    def endorse(self, serder):
        """
        Returns msg with own endorsement of msg from serder with attached signature
        groups based on own pre transferable or non-transferable.
        Useful for endorsing key state message when provided via serder from
        Kever.state()
        Future add support for processing into db once have support for storing
           key state in db.
        """
        if self.kever.prefixer.transferable:
            # create SealEvent for endorsers est evt whose keys use to sign
            seal = eventing.SealEvent(i=self.kever.prefixer.qb64,
                                      s=hex(self.kever.lastEst.s),
                                      d=self.kever.lastEst.d)
            # sign serder event
            sigers = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=True)
            msg = eventing.messagize(serder=serder,
                                     sigers=sigers,
                                     seal=seal,
                                     pipelined=True)

        else:
            # sign serder event
            cigars = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=False)
            msg = eventing.messagize(serder=serder,
                                     cigars=cigars,
                                     pipelined=True)

        return msg


    def verify(self, serder, prefixer, seqner, diger, sigers):
        if prefixer.qb64 in self.kevers:
            # receipted event and receipter in database so get receipter est evt
            # retrieve dig of last event at sn of est evt of receipter.
            sdig = self.db.getKeLast(key=snKey(pre=prefixer.qb64b,
                                               sn=seqner.sn))
            if sdig is None:
                # receipter's est event not yet in receipters's KEL
                raise UnverifiedProofError("key event sn {} for pre {} is not yet in KEL"
                                           "".format(seqner.sn, prefixer.qb64))


            # retrieve last event itself of receipter est evt from sdig
            sraw = self.db.getEvt(key=dgKey(pre=prefixer.qb64b, dig=bytes(sdig)))
            # assumes db ensures that sraw must not be none because sdig was in KE
            sserder = Serder(raw=bytes(sraw))
            if not sserder.compare(diger=diger):  # endorser's dig not match event
                raise ValidationError("Bad proof sig group at sn = {}"
                                      " for ksn = {}."
                                      "".format(seqner.sn, sserder.ked))

            # verify sigs
            sverfers = sserder.verfers
            if not sverfers:
                raise ValidationError("Invalid key state endorser's est. event"
                                      " dig = {} for ksn from pre ={}, "
                                      "no keys."
                                      "".format(diger.qb64, prefixer.qb64))

            for siger in sigers:
                if siger.index >= len(sverfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(siger.index))
                siger.verfer = sverfers[siger.index]  # assign verfer
                if not siger.verfer.verify(siger.raw, serder.raw):  # verify each sig
                    return False

            return True
        else:
            return False


    def replay(self, pre=None, fn=0):
        """
        Returns replay of FEL first seen event log for pre starting from fn
        Default pre is own .pre

        Parameters:
            pre is qb64 str or bytes of identifier prefix.
                default is own .pre
            fn is int first seen ordering number

        """
        if not pre:
            pre = self.pre
        msgs = bytearray()
        for msg in self.db.clonePreIter(pre=pre, fn=fn):
            msgs.extend(msg)
        return msgs


    def replayAll(self, key=b''):
        """
        Returns replay of FEL first seen event log for all pre starting at key

        Parameters:
            key (bytes): fnKey(pre, fn)

        """
        msgs = bytearray()
        for msg in self.db.cloneAllPreIter(key=key):
            msgs.extend(msg)
        return msgs


    def makeOwnEvent(self, sn):
        """
        Returns: messagized bytearray message with attached signatures of
                 own event at sequence number sn from retrieving event at sn
                 and associated signatures from database.

        Parameters:
            sn is int sequence number of event
        """
        msg = bytearray()
        dig = self.db.getKeLast(dbing.snKey(self.pre, sn))
        if dig is None:
            raise kering.MissingEntryError("Missing event for pre={} at sn={}."
                                           "".format(self.pre, sn))
        dig = bytes(dig)
        key = dbing.dgKey(self.pre, dig)  # digest key
        msg.extend(self.db.getEvt(key))
        msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=self.db.cntSigs(key)).qb64b)  # attach cnt
        for sig in self.db.getSigsIter(key):
            msg.extend(sig)  # attach sig
        return (msg)


    def makeOwnInception(self):
        """
        Returns: messagized bytearray message with attached signatures of
                 own inception event by retrieving event and signatures
                 from database.
        """
        return self.makeOwnEvent(sn=0)


    def processCues(self, cues):
        """
        Returns bytearray of messages as a result of processing all cues

        Parameters:
           cues is deque of cues
        """
        msgs = bytearray()  # outgoing messages
        for msg in self.processCuesIter(cues):
            msgs.extend(msg)
        return msgs


    def processCuesIter(self, cues):
        """
        Iterate through cues and yields one or more msgs for each cue.

        Parameters:
            cues is deque of cues

        """
        while cues:  # iteratively process each cue in cues
            msgs = bytearray()
            cue = cues.popleft()
            cueKin = cue["kin"]  # type or kind of cue

            if cueKin in ("receipt", ):  # cue to receipt a received event from other pre
                cuedSerder = cue["serder"]  # Serder of received event for other pre
                cuedKed = cuedSerder.ked
                cuedPrefixer = coring.Prefixer(qb64=cuedKed["i"])
                logger.info("%s got cue: kin=%s\n%s\n\n", self.pre, cueKin,
                            json.dumps(cuedKed, indent=1))

                if cuedKed["t"] == coring.Ilks.icp:
                    dgkey = dbing.dgKey(self.pre, self.iserder.dig)
                    found = False
                    if cuedPrefixer.transferable:  # find if have rct from other pre for own icp
                        for quadruple in self.db.getVrcsIter(dgkey):
                            if bytes(quadruple).decode("utf-8").startswith(cuedKed["i"]):
                                found = True  # yes so don't send own inception
                    else:  # find if already rcts of own icp
                        for couple in self.db.getRctsIter(dgkey):
                            if bytes(couple).decode("utf-8").startswith(cuedKed["i"]):
                                found = True  # yes so don't send own inception

                    if not found:  # no receipt from remote so send own inception
                        # no vrcs or rct of own icp from remote so send own inception
                        msgs.extend(self.makeOwnInception())

                msgs.extend(self.receipt(cuedSerder))
                yield msgs

            elif cueKin in ("replay", ):
                msgs = cue["msgs"]
                yield msgs


class HabitatDoer(doing.Doer):
    """
    Basic Habitat Doer  to initialize habitat databases .ks and .db

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.

    Attributes:
        .habitat is Habitat subclass

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .exit is exit context method
        .close is close context method
        .abort is abort context method

    Hidden:
        ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
        ._tock is hidden attribute for .tock property
    """

    def __init__(self, habitat, **kwa):
        """
        Parameters:
           habitat (Habitat): instance
        """
        super(HabitatDoer, self).__init__(**kwa)
        self.habitat = habitat


    def enter(self):
        """"""
        if not self.habitat.inited:
            self.habitat.setup(**self.habitat._inits)


    def exit(self):
        """"""
        pass
