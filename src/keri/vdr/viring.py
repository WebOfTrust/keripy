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

from .. import kering, core
from ..app import signing
from ..core import coring, serdering, indexing, counting
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
        .tibs is named sub DB implemented as CesrDupSuber with klas=indexing.Siger
            for indexed backer signatures of event.
            Backers always have nontransferable identifier prefixes.
            The index is the offset of the backer into the backer list
            of the anchored management event wrt the receipted event.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event.
            Multiple values per key in lexicographic order.
        .oots is named subDB instance of OnIoDupSuber for of out of order escrowed event tables
            that a composite key of the form <pre><sep><on> to serialized event digests.
            Values are digests used to lookup event in .tvts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            Only one value per DB key is allowed
        .baks is named subDB instance of IoDupSuber which represents an 
            ordered list of backers at given point in management TEL.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed
        .twes is named subDB instance of OnIoDupSuber for partially witnessed escrowed event tables
            that map key composites of the form <pre><sep><on> to serialized event digests.
            Values are digests used to lookup event in .tvts sub DB
            DB is keyed by identifier prefix plus sequence number of tel event
            Only one value per DB key is allowed
        .taes is named subDB instance of OnIoDupSuber for anchorless escrowed event tables that map
            a composite key of the form <pre><sep><on> to serialized event digest.
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
        self._tevers = rbdict()
        self._tevers.reger = self  # assign db for read through cache of tevers
        self._tevers.db = kwa.get("db", self)

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

        self.tvts = subing.Suber(db=self, subkey='tvts.')
        self.tels = subing.OnSuber(db=self, subkey='tels.')
        self.ancs = subing.CatCesrSuber(db=self, subkey='ancs.',
                        klas=(coring.Number, coring.Diger))
        self.baks = subing.IoDupSuber(db=self, subkey='baks.')
        self.tibs = subing.CesrDupSuber(db=self, subkey='tibs.', klas=indexing.Siger)
        self.oots = subing.OnIoDupSuber(db=self, subkey='oots')
        self.twes = subing.OnIoDupSuber(db=self, subkey='twes')
        self.taes = subing.OnIoDupSuber(db=self, subkey='taes')
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
                                         klas=(coring.Prefixer, coring.Number, coring.Diger))

        # all sad path ssgs (sad pathed indexed signature serializations) maps SAD quinkeys
        # given by quintuple (saider.qb64, path, prefixer.qb64, number.qb64, diger.qb64)
        # of credential and trans signer's key state est evt to val Siger for each
        # signature.
        self.spsgs = subing.CesrIoSetSuber(db=self, subkey='ssgs.', klas=indexing.Siger)

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
                                             klas=(coring.Prefixer, coring.Number, coring.Diger))
        # TEL multisig anchor escrow
        self.tmse = subing.CatCesrIoSetSuber(db=self, subkey='tmse.',
                                             klas=(coring.Prefixer, coring.Number, coring.Diger))
        # TEL event dissemination escrow
        self.tede = subing.CatCesrIoSetSuber(db=self, subkey='tede.',
                                             klas=(coring.Prefixer, coring.Number, coring.Saider))

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
            creder, prefixer, number, asaider = self.cloneCred(said=key)
            atc = bytearray(signing.serialize(creder, prefixer, number, saider))
            del atc[0:creder.size]

            regk = creder.regid
            status = self.tevers[regk].vcState(saider.qb64)
            schemer = db.schema.get(creder.schema)

            iss = bytearray(self.cloneTvtAt(creder.said, sn=0))
            iserder = serdering.SerderKERI(raw=iss)
            issatc = bytes(iss[iserder.size:])
            del iss[0:iserder.size]
            if status.et in [coring.Ilks.rev, coring.Ilks.brv]:
                rev = bytearray(self.cloneTvtAt(creder.said, sn=1))
                rserder = serdering.SerderKERI(raw=rev)
                revatc = bytes(rev[rserder.size:])
                del rev[0:rserder.size]

            chainSaids = []
            for k, p in (creder.edge.items() if creder.edge is not None else {}):
                if k == "d":
                    continue

                if not isinstance(p, dict):
                    continue

                chainSaids.append(coring.Saider(qb64=p["n"]))
            chains = self.cloneCreds(chainSaids, db)

            cred = dict(
                sad=creder.sad,
                atc=atc.decode("utf-8"),
                iss=iserder.sad,
                issatc=issatc.decode("utf-8"),
                rev=rserder.sad if status.et in [coring.Ilks.rev, coring.Ilks.brv] else None,
                revatc=revatc.decode("utf-8") if status.et in [coring.Ilks.rev, coring.Ilks.brv] else None,
                pre=creder.issuer,
                schema=schemer.sed,
                chains=chains,
                status=asdict(status),
                anchor=dict(
                    pre=prefixer.qb64,
                    sn=number.sn,
                    d=asaider.qb64
                )
            )

            ctr = core.Counter(qb64b=iss, strip=True, version=kering.Vrsn_1_0)
            if ctr.code == counting.CtrDex_1_0.AttachmentGroup:
                ctr = core.Counter(qb64b=iss, strip=True, version=kering.Vrsn_1_0)

            if ctr.code == counting.CtrDex_1_0.SealSourceCouples:
                coring.Number(qb64b=iss, strip=True)
                saider = coring.Saider(qb64b=iss)

                anc = db.cloneEvtMsg(pre=creder.issuer, fn=0, dig=saider.qb64b)
                aserder = serdering.SerderKERI(raw=anc)
                ancatc = bytes(anc[aserder.size:])
                cred['anc'] = aserder.sad
                cred['ancatc'] = ancatc.decode("utf-8"),

            if status.et in [coring.Ilks.rev, coring.Ilks.brv]:
                ctr = core.Counter(qb64b=rev, strip=True, version=kering.Vrsn_1_0)
                if ctr.code == counting.CtrDex_1_0.AttachmentGroup:
                    ctr = core.Counter(qb64b=rev, strip=True, version=kering.Vrsn_1_0)

                if ctr.code == counting.CtrDex_1_0.SealSourceCouples:
                    coring.Number(qb64b=rev, strip=True)
                    saider = coring.Saider(qb64b=rev)

                    anc = db.cloneEvtMsg(pre=creder.issuer, fn=0, dig=saider.qb64b)
                    aserder = serdering.SerderKERI(raw=anc)
                    ancatc = bytes(anc[aserder.size:])
                    cred['revanc'] = aserder.sad
                    cred['revancatc'] = ancatc.decode("utf-8"),

            creds.append(cred)

        return creds

    def logCred(self, creder, prefixer, number, diger):
        """ Save the base credential and seals (est evt+sigs quad) with no indices.

        Parameters:
            creder (Creder): that contains the credential to process
            prefixer (Prefixer): prefix (AID or TEL) of event anchoring credential
            number (Number): sequence number of event anchoring credential
            diger (Diger): digest of anchoring event for credential

        """
        key = creder.said
        self.cancs.pin(keys=key, val=[prefixer, number, diger])
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
        if creder is None:
            raise kering.MissingEntryError(f"no credential found with said {said}")
        prefixer, number, saider = self.cancs.get(keys=(said,))
        return creder, prefixer, number, saider

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

        for _, fn, dig in self.tels.getOnItemIterAll(keys=pre, on=fn):
            msg = self.cloneTvt(pre, dig)
            yield msg

    def cloneTvtAt(self, pre, sn=0):
        snkey = dbing.snKey(pre, sn)
        dig = self.tels.get(keys=snkey)
        return self.cloneTvt(pre, dig)

    def cloneTvt(self, pre, dig):
        msg = bytearray()  # message
        atc = bytearray()  # attachments
        dgkey = dbing.dgKey(pre, dig)  # get message
        if not (raw := self.tvts.get(keys=dgkey)):
            raise kering.MissingEntryError("Missing event for dig={}.".format(dig))
        msg.extend(raw.encode("utf-8"))

        # add indexed backer signatures to attachments
        if tibs := self.tibs.get(keys=(pre, dig)):
            atc.extend(core.Counter(core.Codens.WitnessIdxSigs, count=len(tibs),
                                    version=kering.Vrsn_1_0).qb64b)
            for tib in tibs:
                atc.extend(tib.qb64b)

        # add authorizer (delegator/issure) source seal event couple to attachments
        couple = self.ancs.get(keys=dgkey)
        if couple is not None:
            number, diger = couple
            seqner = coring.Seqner(sn=number.sn)
            saider = coring.Saider(qb64=diger.qb64)
            atc.extend(core.Counter(core.Codens.SealSourceCouples, count=1,
                                    version=kering.Vrsn_1_0).qb64b)
            atc.extend(seqner.qb64b)
            atc.extend(saider.qb64b)

        # prepend pipelining counter to attachments
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        pcnt = core.Counter(core.Codens.AttachmentGroup, count=(len(atc) // 4),
                            version=kering.Vrsn_1_0).qb64b
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
            screder, prefixer, number, saider = self.cloneCred(said=said)

            atc = bytearray(core.Counter(core.Codens.SealSourceTriples, count=1,
                                         version=kering.Vrsn_1_0).qb64b)
            atc.extend(prefixer.qb64b)
            atc.extend(number.qb64b)
            atc.extend(saider.qb64b)

            sources.append((screder, atc))
            sources.extend(self.sources(db, screder))

        return sources


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
    prf.extend(core.Counter(core.Codens.TransIdxSigGroups, count=1,
                            version=kering.Vrsn_1_0).qb64b)
    prf.extend(prefixer.qb64b)
    prf.extend(seqner.qb64b)
    prf.extend(diger.qb64b)

    prf.extend(core.Counter(core.Codens.ControllerIdxSigs, count=len(sigers),
                            version=kering.Vrsn_1_0).qb64b)
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
    craw.extend(core.Counter(core.Codens.AttachmentGroup, count=(len(proof) // 4),
                             version=kering.Vrsn_1_0).qb64b)
    craw.extend(proof)

    return craw
