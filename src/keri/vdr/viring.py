# -*- encoding: utf-8 -*-
"""
keri.db.viring module

VIR  Verifiable Issuance(Revocation) Registry

Provides public simple Verifiable Credential Issuance/Revocation Registry
A special purpose Verifiable Data Registry (VDR)
"""

from dataclasses import dataclass, field, asdict
from  ordered_set import OrderedSet as oset

from ..db import koming, subing, escrowing

from .. import kering
from ..app import signing
from ..core import coring, serdering
from ..db import dbing, basing
from ..db.dbing import snKey
from ..help import helping
from ..vc import proving
from ..vdr import eventing


class rbdict(dict):
    """ Reger backed read through cache for registry state

    Subclass of dict that has db and reger as attributes and employs read
    through cache from db Reger.stts of registry states to reload tever from
    state in database when not found in memory as dict item.
    """
    __slots__ = ('db', 'reger')  # no .__dict__ just for db reference

    def __init__(self, *pa, **kwa):
        super(rbdict, self).__init__(*pa, **kwa)
        self.db = None
        self.reger = None

    def __getitem__(self, k):

        try:
            return super(rbdict, self).__getitem__(k)
        except KeyError as ex:
            if not self.db or not self.reger:
                raise ex  # reraise KeyError
            if (rsr := self.reger.states.get(keys=k)) is None:
                raise ex  # reraise KeyError
            try:
                tever = eventing.Tever(rsr=rsr, db=self.db, reger=self.reger)
            except kering.MissingEntryError:  # no kel event for keystate
                raise ex  # reraise KeyError
            super(rbdict, self).__setitem__(k, tever)
            return tever

    def __setitem__(self, key, item):
        super(rbdict, self).__setitem__(key, item)
        self.reger.states.pin(keys=key, val=item.state())

    def __delitem__(self, key):
        super(rbdict, self).__delitem__(key)
        self.reger.states.rem(keys=key)

    def __contains__(self, k):
        if not super(rbdict, self).__contains__(k):
            try:
                self.__getitem__(k)
                return True
            except KeyError:
                return False
        else:
            return True

    def get(self, k, default=None):
        """Override of dict get method

        Parameters:
            k (str): key for dict
            default: default value to return if not found

        Returns:
            tever: converted from underlying dict or database

        """
        if not super(rbdict, self).__contains__(k):
            return default
        else:
            return self.__getitem__(k)


@dataclass
class RegistryRecord:
    """ Registry Key keyed by Registry name
    """
    registryKey: str
    prefix: str


@dataclass
class RegStateRecord(basing.RawRecord):  # reger.state
    """
    Registry Event Log (REL) State information

    (see reger.state at 'stts' for database that holds these records  keyed by
    Registry SAID, i field)

    Attributes:
        vn (list[int]): version number [major, minor]
        i (str): registry SAID qb64 (registry inception event SAID)
        s (str): sequence number of latest event in KEL as hex str
        d (str): latest registry event digest qb64
        ii (str): registry issuer identifier aid qb64
        dt (str): datetime iso-8601 of registry state record update, usually now
        et (str): event packet type (ilk)
        bt (str): backer threshold hex num
        b (list[str]): backer aids qb64
        c (list[str]): config traits

    Note: the seal anchor dict 'a' field is not included in the state notice
    because it may be verbose and would impede the main purpose of a notice which
    is to trigger the download of the latest events, which would include the
    anchored seals.

    rsr = viring.RegStateRecord(
            vn=list(version), # version number as list [major, minor]
            i=ri,  # qb64 registry SAID
            s="{:x}".format(sn),  # lowercase hex string no leading zeros
            d=said,
            ii=pre,
            dt=dts,
            et=eilk,
            bt="{:x}".format(toad),  # hex string no leading zeros lowercase
            b=wits,  # list of qb64 may be empty
            c=cnfg if cnfg is not None else [],
            )

    """
    vn: list[int] = field(default_factory=list)  # version number [major, minor] round trip serializable
    i: str = ''  # identifier prefix qb64
    s: str = '0'  # sequence number of latest event in KEL as hex str
    d: str = ''  # latest event digest qb64
    ii: str = ''  # issuer identifier of registry aid qb64
    dt: str = ''  # datetime of update of state record
    et: str = ''  # TEL evt packet type (ilk)
    bt: str = '0'  # backer threshold hex num str
    b: list = field(default_factory=list)  # backer AID list qb64
    c: list[str] = field(default_factory=list)  # config trait list


@dataclass
class VcStateRecord(basing.RawRecord):
    vn: list[str] = field(default_factory=list)  # version number [major, minor] round trip serializable
    i: str = ''  # identifier prefix qb64
    s: str = '0'  # sequence number of latest event in KEL as hex str
    d: str = ''  # latest event digest qb64
    ri: str = ''  # registry identifier of registry aid qb64
    ra: dict = field(default_factory=dict)  # registry anchor for registry with backers
    a: dict = field(default_factory=dict)  # seal for anchor in KEL
    dt: str = ''  # datetime of update of state record
    et: str = ''  # TEL evt packet type (ilk)


def openReger(name="test", **kwa):
    """ Returns contextmanager generated by openLMDB but with Baser instance

    Parameters:
        name (str): registry database name
        **kwa (dict) keyword arguments to pass to LMDB

    """
    return dbing.openLMDB(cls=Reger, name=name, **kwa)


class Reger(dbing.LMDBer):
    """ Reger sets up named sub databases for TEL registry

    Attributes:
        see superclass LMDBer for inherited attributes


        .tvts is named sub DB whose values are serialized TEL events
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            Only one value per DB key is allowed
        .tels is named sub DB of transaction event log tables that map sequence
            numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .tvts sub DB
            DB is keyed by identifier prefix plus sequence number of tel event
            Only one value per DB key is allowed
        .tibs is named sub DB of indexed backer signatures of event
            Backers always have nontransferable indetifier prefixes.
            The index is the offset of the backer into the backer list
            of the anchored management event wrt the receipted event.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed
        .oots is named sub DB of out of order escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .tvts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            Only one value per DB key is allowed
        .baks is named sub DB of ordered list of backers at given point in
            management TEL.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed
        .twes is named sub DB of partially witnessed escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .tvts sub DB
            DB is keyed by identifier prefix plus sequence number of tel event
            Only one value per DB key is allowed
        .taes is named sub DB of anchorless escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .tvts sub DB
            DB is keyed by identifier prefix plus sequence number of tel event
            Only one value per DB key is allowed
        .ancs is a named sub DB of anchors to KEL events.  Quadlet
            Each quadruple is concatenation of  four fully qualified items
            of validator. These are: transferable prefix, plus latest establishment
            event sequence number plus latest establishment event digest,
            plus indexed event signature.
            When latest establishment event is multisig then there will
            be multiple quadruples one per signing key, each a dup at same db key.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            Only one value per DB key is allowed

        .regs is named subDB instance of Komer that maps registry names to registry keys
            key is habitat name str
            value is serialized RegistryRecord dataclass


    """
    TailDirPath = "keri/reg"
    AltTailDirPath = ".keri/reg"
    TempPrefix = "keri_reg_"

    def __init__(self, headDirPath=None, reopen=True, **kwa):
        """
        Setup named sub databases.

        Inherited Parameters:
            name (str): directory path name differentiator for main database
                When system employs more than one keri database, name allows
                differentiating each instance by name
            temp (boolean,): assign to .temp
                True then open in temporary directory, clear on close
                Othewise then open persistent directory, do not clear on close
            headDirPath (Optional(str)): head directory pathname for main database
                If not provided use default .HeadDirpath
            mode (int): numeric os dir permissions for database directory
            reopen (boolean,): IF True then database will be reopened by this init

        Notes:

        dupsort=True for sub DB means allow unique (key,pair) duplicates at a key.
        Duplicate means that is more than one value at a key but not a redundant
        copies a (key,value) pair per key. In other words the pair (key,value)
        must be unique both key and value in combination.
        Attempting to put the same (key,value) pair a second time does
        not add another copy.

        Duplicates are inserted in lexocographic order by value, insertion order.

        """

        self.registries = oset()
        if "db" in kwa:
            self._tevers = rbdict()
            self._tevers.reger = self  # assign db for read thorugh cache of kevers
            self._tevers.db = kwa["db"]
        else:
            self._tevers = dict()

        super(Reger, self).__init__(headDirPath=headDirPath, reopen=reopen, **kwa)


    @property
    def tevers(self):
        """ Returns ._tevers
        tevers getter
        """
        return self._tevers

    def reopen(self, **kwa):
        """ Open sub databases

        Parameters:
            **kwa (dict): keyword arguments passed to super.reopen

        """
        super(Reger, self).reopen(**kwa)

        # Create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.

        self.tvts = self.env.open_db(key=b'tvts.')
        self.tels = self.env.open_db(key=b'tels.')
        self.ancs = self.env.open_db(key=b'ancs.')
        self.tibs = self.env.open_db(key=b'tibs.', dupsort=True)
        self.baks = self.env.open_db(key=b'baks.', dupsort=True)
        self.oots = self.env.open_db(key=b'oots.')
        self.twes = self.env.open_db(key=b'twes.')
        self.taes = self.env.open_db(key=b'taes.')
        self.tets = subing.CesrSuber(db=self, subkey='tets.', klas=coring.Dater)

        # Registry state made of RegStateRecord.
        # Each registry has registry event log keyed by registry identifier
        self.states = koming.Komer(db=self,
                                   schema=RegStateRecord,
                                   subkey='stts.')
        #self.states = subing.SerderSuber(db=self, subkey='stts.')  # registry event state

        # Holds the credential
        self.creds = subing.SerderSuber(db=self, subkey="creds.", klas=serdering.SerderACDC)

        # database of anchors to credentials.  prefix is either AID with direct credential
        # anchor or TEL event AID (same as credential SAID) when credential uses revocation registry
        self.cancs = subing.CatCesrSuber(db=self, subkey='cancs.',
                                         klas=(coring.Prefixer, coring.Seqner, coring.Saider))

        # all sad path ssgs (sad pathed indexed signature serializations) maps SAD quinkeys
        # given by quintuple (saider.qb64, path, prefixer.qb64, seqner.q64, diger.qb64)
        # of credential and trans signer's key state est evt to val Siger for each
        # signature.
        self.spsgs = subing.CesrIoSetSuber(db=self, subkey='ssgs.', klas=coring.Siger)

        # all sad path scgs  (sad pathed non-indexed signature serializations) maps
        # couple (SAD SAID, path) to couple (Verfer, Cigar) of nontrans signer of signature in Cigar
        # nontrans qb64 of Prefixer is same as Verfer
        self.spcgs = subing.CatCesrIoSetSuber(db=self, subkey='scgs.',
                                              klas=(coring.Verfer, coring.Cigar))

        # Index of credentials processed and saved.  Indicates fully verified (even if revoked)
        self.saved = subing.CesrSuber(db=self, subkey='saved.', klas=coring.Saider)
        # Index of credentials by issuer.  My credentials issued, key == hab.pre
        self.issus = subing.CesrDupSuber(db=self, subkey='issus.', klas=coring.Saider)
        # Index of credentials by subject.  My credentials received, key == hab.pre
        self.subjs = subing.CesrDupSuber(db=self, subkey='subjs.', klas=coring.Saider)
        # Index of credentials by schema
        self.schms = subing.CesrDupSuber(db=self, subkey='schms.', klas=coring.Saider)

        # Missing reegistry escrow
        self.mre = subing.CesrSuber(db=self, subkey='mre.', klas=coring.Dater)
        # Broken chain escrow
        self.mce = subing.CesrSuber(db=self, subkey='mce.', klas=coring.Dater)
        # Missing schema escrow
        self.mse = subing.CesrSuber(db=self, subkey='mse.', klas=coring.Dater)

        # Collection of sub-dbs for persisting Registry Txn State Notices
        self.txnsb = escrowing.Broker(db=self, subkey="txn.")

        # registry keys keyed by Registry name
        self.regs = koming.Komer(db=self,
                                 subkey='regs.',
                                 schema=RegistryRecord, )

        # TEL partial witness escrow
        self.tpwe = subing.CatCesrIoSetSuber(db=self, subkey='tpwe.',
                                             klas=(coring.Prefixer, coring.Seqner, coring.Saider))

        # TEL multisig anchor escrow
        self.tmse = subing.CatCesrIoSetSuber(db=self, subkey='tmse.',
                                             klas=(coring.Prefixer, coring.Seqner, coring.Saider))

        # TEL event disemination escrow
        self.tede = subing.CatCesrIoSetSuber(db=self, subkey='tede.',
                                             klas=(coring.Prefixer, coring.Seqner, coring.Saider))

        # Completed TEL event
        self.ctel = subing.CesrSuber(db=self, subkey='ctel.',
                                     klas=coring.Saider)

        # Credential Missing Signature Escrow
        self.cmse = subing.SerderSuber(db=self, subkey="cmse.", klas=serdering.SerderACDC)

        # Completed Credentials
        self.ccrd = subing.SerderSuber(db=self, subkey="ccrd.", klas=serdering.SerderACDC)

        return self.env

    def cloneCreds(self, saids, db):
        """ Returns fully expanded credential with chained credentials attached.

        Parameters:
           saids (list): of Saider objects:
           db (Baser): baser object to load schema

        Returns:
            list: fully hydrated credentials with full chains provided

        """
        creds = []
        for saider in saids:
            key = saider.qb64
            creder, prefixer, seqner, asaider = self.cloneCred(said=key)
            atc = bytearray(signing.serialize(creder, prefixer, seqner, saider))
            del atc[0:creder.size]

            iss = bytearray(self.cloneTvtAt(creder.said))
            iserder = serdering.SerderKERI(raw=iss)
            issatc = bytes(iss[iserder.size:])

            del iss[0:iserder.size]

            chainSaids = []
            for k, p in (creder.edge.items() if creder.edge is not None else {}):
                if k == "d":
                    continue

                if not isinstance(p, dict):
                    continue

                chainSaids.append(coring.Saider(qb64=p["n"]))
            chains = self.cloneCreds(chainSaids, db)

            regk = creder.regi
            status = self.tevers[regk].vcState(saider.qb64)
            schemer = db.schema.get(creder.schema)

            cred = dict(
                sad=creder.sad,
                atc=atc.decode("utf-8"),
                iss=iserder.sad,
                issatc=issatc.decode("utf-8"),
                pre=creder.issuer,
                schema=schemer.sed,
                chains=chains,
                status=asdict(status),
                anchor=dict(
                    pre=prefixer.qb64,
                    sn=seqner.sn,
                    d=asaider.qb64
                )
            )

            ctr = coring.Counter(qb64b=iss, strip=True)
            if ctr.code == coring.CtrDex.AttachedMaterialQuadlets:
                ctr = coring.Counter(qb64b=iss, strip=True)

            if ctr.code == coring.CtrDex.SealSourceCouples:
                coring.Seqner(qb64b=iss, strip=True)
                saider = coring.Saider(qb64b=iss)

                anc = db.cloneEvtMsg(pre=creder.issuer, fn=0, dig=saider.qb64b)
                aserder = serdering.SerderKERI(raw=anc)
                ancatc = bytes(anc[aserder.size:])
                cred['anc'] = aserder.sad
                cred['ancatc'] = ancatc.decode("utf-8"),

            creds.append(cred)

        return creds

    def logCred(self, creder, prefixer, seqner, saider):
        """ Save the base credential and seals (est evt+sigs quad) with no indices.

        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix (AID or TEL) of event anchoring credential
            seqner (Seqner): sequence number of event anchoring credential
            saider (Diger) digest of anchoring event for credential

        """
        key = creder.said
        self.cancs.pin(keys=key, val=[prefixer, seqner, saider])
        self.creds.put(keys=key, val=creder)

    def cloneCred(self, said):
        """ Load base credential and CESR proof signatures from database.

        Base credential and all signatures are returned from the credential
        data store.  If root is specified, all signatures are transposed to have
        that path as the root.  This is used to embed the credential in another SAD
        at the location of the specified root.

        Parameters:
            said(str or bytes): qb64 SAID of credential

        """

        creder = self.creds.get(keys=(said,))
        prefixer, seqner, saider = self.cancs.get(keys=(said,))
        return creder, prefixer, seqner, saider

    def clonePreIter(self, pre, fn=0):
        """ Iterator of first seen event messages

        Returns iterator of first seen event messages with attachments for the
        TEL prefix pre starting at fir`st seen order number, fn.
        Essentially a replay in first seen order with attachments

        Parameters:
            pre (bytes): qb64 identifier prefix of registry state TEL
            fn (int): first seen ordinal

        Returns:
            iterator: bytearray per serializeed event msg

        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for fn, dig in self.getTelItemPreIter(pre, fn=fn):
            msg = self.cloneTvt(pre, dig)
            yield msg

    def cloneTvtAt(self, pre, sn=0):
        snkey = dbing.snKey(pre, sn)
        dig = self.getTel(key=snkey)
        return self.cloneTvt(pre, dig)

    def cloneTvt(self, pre, dig):
        msg = bytearray()  # message
        atc = bytearray()  # attachments
        dgkey = dbing.dgKey(pre, dig)  # get message
        if not (raw := self.getTvt(key=dgkey)):
            raise kering.MissingEntryError("Missing event for dig={}.".format(dig))
        msg.extend(raw)

        # add indexed backer signatures to attachments
        if tibs := self.getTibs(key=dgkey):
            atc.extend(coring.Counter(code=coring.CtrDex.WitnessIdxSigs,
                                      count=len(tibs)).qb64b)
            for tib in tibs:
                atc.extend(tib)

        # add authorizer (delegator/issure) source seal event couple to attachments
        couple = self.getAnc(dgkey)
        if couple is not None:
            atc.extend(coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                      count=1).qb64b)
            atc.extend(couple)

        # prepend pipelining counter to attachments
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        pcnt = coring.Counter(code=coring.CtrDex.AttachedMaterialQuadlets,
                              count=(len(atc) // 4)).qb64b
        msg.extend(pcnt)
        msg.extend(atc)
        return msg

    def sources(self, db, creder):
        """ Returns raw bytes of any source ('e') credential that is in our database

        Parameters:
            db (LMDBer): table to search
            creder (Creder): root credential

        Returns:
            list: credential sources as resolved from `e` in creder.crd

        """
        chains = creder.edge if creder.edge is not None else {}
        saids = []
        for key, source in chains.items():
            if key == 'd':
                continue

            if not isinstance(source, dict):
                continue

            saids.append(source['n'])

        sources = []
        for said in saids:
            screder, prefixer, seqner, saider = self.cloneCred(said=said)

            atc = bytearray(coring.Counter(coring.CtrDex.SealSourceTriples, count=1).qb64b)
            atc.extend(prefixer.qb64b)
            atc.extend(seqner.qb64b)
            atc.extend(saider.qb64b)

            sources.append((screder, atc))
            sources.extend(self.sources(db, screder))

        return sources

    def putTvt(self, key, val):
        """
        Use dgKey()
        Write serialized VC bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.tvts, key, val)

    def setTvt(self, key, val):
        """
        Use dgKey()
        Write serialized VC bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.tvts, key, val)

    def getTvt(self, key):
        """
        Use dgKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.tvts, key)

    def delTvt(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.tvts, key)

    def putTel(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.tels, key, val)

    def setTel(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.tels, key, val)

    def getTel(self, key):
        """
        Use snKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.tels, key)

    def delTel(self, key):
        """
        Use snKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.tels, key)

    def getTelItemPreIter(self, pre, fn=0):
        """
        Returns iterator of all (fn, dig) duples in first seen order for all events
        with same prefix, pre, in database. Items are sorted by fnKey(pre, fn)
        where fn is first seen order number int.
        Returns a First Seen Event Log TEL.
        Returned items are duples of (fn, dig): Where fn is first seen order
        number int and dig is event digest for lookup in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            pre is bytes of itdentifier prefix
            fn is int fn to resume replay. Earliset is fn=0
        """
        return self.getAllOrdItemPreIter(db=self.tels, pre=pre, on=fn)

    def cntTels(self, pre, fn=0):
        """
        Returns count of all (fn, dig)  for all events
        with same prefix, pre, in database.

        Parameters:
            pre is bytes of itdentifier prefix
            fn is int fn to resume replay. Earliset is fn=0
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes

        return self.cntValsAllPre(db=self.tels, pre=pre, on=fn)

    def getTibs(self, key):
        """
        Use dgKey()
        Return list of indexed witness signatures at key
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.tibs, key)

    def getTibsIter(self, key):
        """
        Use dgKey()
        Return iterator of indexed witness signatures at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.tibs, key)

    def putTibs(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes indexed witness signatures vals to key
        Adds to existing signatures at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.tibs, key, vals)

    def addTib(self, key, val):
        """
        Use dgKey()
        Add indexed witness signature val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.tibs, key, val)

    def cntTibs(self, key):
        """
        Use dgKey()
        Return count of indexed witness signatures at key
        Returns zero if no entry at key
        """
        return self.cntVals(self.tibs, key)

    def delTibs(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.tibs, key, val)

    def putTwe(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.twes, key, val)

    def setTwe(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.twes, key, val)

    def getTwe(self, key):
        """
        Use snKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.twes, key)

    def delTwe(self, key):
        """
        Use snKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.twes, key)

    def putTae(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.taes, key, val)

    def setTae(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.taes, key, val)

    def getTae(self, key):
        """
        Use snKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.taes, key)

    def getTaeItemIter(self):
        """
        Return iterator of all items in .taes

        """
        return self.getAllItemIter(self.taes, split=True)

    def delTae(self, key):
        """
        Use snKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.taes, key)


    def putOot(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.oots, key, val)

    def setOot(self, key, val):
        """
        Use snKey()
        Write serialized VC bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.oots, key, val)

    def getOot(self, key):
        """
        Use snKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.oots, key)

    def getOotItemIter(self):
        """
        Return iterator of all items in .taes

        """
        return self.getAllItemIter(self.oots, split=True)

    def delOot(self, key):
        """
        Use snKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.oots, key)


    def putAnc(self, key, val):
        """
        Use dgKey()
        Write serialized VC bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.ancs, key, val)

    def setAnc(self, key, val):
        """
        Use dgKey()
        Write serialized VC bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.ancs, key, val)

    def getAnc(self, key):
        """
        Use dgKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.ancs, key)

    def delAnc(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.ancs, key)


    def putBaks(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes prefixes to key
        Adds to existing backers at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.baks, key, vals)


    def addBak(self, key, val):
        """
        Use dgKey()
        Add prefix val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.baks, key, val)


    def getBaks(self, key):
        """
        Use dgKey()
        Return list of backer prefixes at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.baks, key)


    def getBaksIter(self, key):
        """
        Use dgKey()
        Return iterator of backer prefixes at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.baks, key)

    def cntBaks(self, key):
        """
        Use dgKey()
        Return count of backer prefixes at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.baks, key)


    def delBaks(self, key):
        """
        Use dgKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.baks, key)


    def delBak(self, key, val):
        """
        Use dgKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.baks, key, val)


def buildProof(prefixer, seqner, diger, sigers):
    """
    Create CESR proof attachment from the quadlet of seal plus signatures on the credential

    Parameters:
        prefixer (Prefixer) Identifier of the issuer of the credential
        seqner (Seqner) is the sequence number of the event used to sign the credential
        diger (Diger) is the digest of the event used to sign the credential
        sigers (list) are the cryptographic signatures on the credential

    """

    prf = bytearray()
    prf.extend(coring.Counter(coring.CtrDex.TransIdxSigGroups, count=1).qb64b)
    prf.extend(prefixer.qb64b)
    prf.extend(seqner.qb64b)
    prf.extend(diger.qb64b)

    prf.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers)).qb64b)
    for siger in sigers:
        prf.extend(siger.qb64b)

    return prf


def messagize(creder, proof):
    """ Create a CESR message format with proof attachment for credential

    Parameters
        creder (Creder): instance of credential
        proof (str): CESR proof attachment

    Returns:
        bytearray: serialized credential with attached proof

    """

    craw = bytearray(creder.raw)
    if len(proof) % 4:
        raise ValueError("Invalid attachments size={}, nonintegral"
                         " quadlets.".format(len(proof)))
    craw.extend(coring.Counter(code=coring.CtrDex.AttachedMaterialQuadlets,
                               count=(len(proof) // 4)).qb64b)
    craw.extend(proof)

    return craw
