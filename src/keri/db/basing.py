# -*- encoding: utf-8 -*-
"""
keri.db.dbing module


import lmdb
db = lmdb.open("/tmp/keri_db_setup_test")
db.max_key_size()
511

The dupsort, integerkey, integerdup, and dupfixed parameters are ignored
if the database already exists.
The state of those settings are persistent and immutable per database.
See _Database.flags() to view the state of those options for an opened database.
A consequence of the immutability of these flags is that the default non-named
database will never have these flags set.

So only need to set dupsort first time opened each other opening does not
need to call it
"""

import os
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, asdict, field
from typing import Optional

import lmdb
from ordered_set import OrderedSet as oset

from hio.base import doing

from . import dbing, koming, subing
from .. import kering

from ..core import coring, eventing, parsing

from .. import help

logger = help.ogler.getLogger()


class dbdict(dict):
    """
    Subclass of dict that has db as attribute and employs read through cash
    from db Baser.stts of kever states to reload kever from state in database
    if not in memory as dict item
    """
    __slots__ = ('db')  # no .__dict__ just for db reference

    def __init__(self, *pa, **kwa):
        super(dbdict, self).__init__(*pa, **kwa)
        self.db = None

    def __getitem__(self, k):
        try:
            return super(dbdict, self).__getitem__(k)
        except KeyError as ex:
            if not self.db:
                raise ex  # reraise KeyError
            if (state := self.db.states.get(keys=k)) is None:
                raise ex  # reraise KeyError
            try:
                kever = eventing.Kever(state=state, db=self.db)
            except kering.MissingEntryError:  # no kel event for keystate
                raise ex  # reraise KeyError
            self.__setitem__(k, kever)
            return kever

    def __contains__(self, k):
        if not super(dbdict, self).__contains__(k):
            try:
                self.__getitem__(k)
                return True
            except KeyError:
                return False
        else:
            return True

    def get(self, k, default=None):
        if not super(dbdict, self).__contains__(k):
            return default
        else:
            return self.__getitem__(k)


@dataclass
class OobiQueryRecord:  # information for responding to OOBI query
    """
    Keyed by cid in oobis field of HabitatRecord  (oobiq).
    Determines which endpoints are allowed as responses to oobi query for cid
    cid is aid of controller with endpoint.
    role is functional role of endpoint provider
    eids are aids of endpoint providers for a role.
    schemes are url schemes of endpoint url

    This record acts as a constraint tree with path cid.role.eid.scheme.
    Partial path specification permits the resultant subtree. Full path
    specification permits only the leaf. No record could be either all allowed
    or none allowed depending on the habitat type or function. Defaults rules
    for each pairing of querier and replier.

    This functionality is aspirational for now. It is likely that we need an
    endpoint identity constraint graph to properly model the endpoint relationship
    permissing constraint structure. For now we just operate with a promiscuous
    constraint policy for endpoint discovery .

    Usage:
        oobiqs: dict[str, OobiQueryRecord] = field(default_factory=dict)
    """
    cid: str = None  # qb64
    role: str = None  # one of kering.Roles None is any or all
    eids: list[str] = field(default_factory=list)  # of qb64  empty is any
    scheme: str = None  # one of kering.Schemes None is any or all

    def __iter__(self):
        return iter(asdict(self))


@dataclass
class OobiRecord:
    """
    Keyed by CID (AID) and role, the minimum information needed for any OOBI
    """
    oobialias: str = None
    said: str = None
    cid: str = None
    eid: str = None
    role: str = None
    date: str = None
    state: str = None
    urls: list = None


@dataclass
class HabitatRecord:  # baser.habs
    """
    Habitat application state information keyed by habitat name (baser.habs)

    Attributes:
        hid (str): identifier prefix of hab qb64
        mid (str | None): group member identifier qb64 when hid is group
        smids (list | None): group signing member identifiers qb64 when hid is group
        rmids (list | None): group signing member identifiers qb64 when hid is group
        watchers: (list[str]) = list of id prefixes qb64 of watchers

    ToDo: NRR
        May need to save midxs for interact event signing by .mhab because
        merfers and migers and mindices are not provided. Reserve members of
        group do not participate in signing so must either ignore or raise error
        if asked to sign interaction event.

        #midxs: tuple[int, int] | None = None # mid index tuple (csi, pni)

    """
    hid: str  # hab own identifier prefix qb64
    mid: str | None = None  # group member identifier qb64 when hid is group
    smids: list | None = None  # group signing member ids when hid is group
    rmids: list | None = None  # group rotating member ids when hid is group
    watchers: list[str] = field(default_factory=list)  # id prefixes qb64 of watchers


@dataclass
class RotateRecord:
    """
    Tracks requests to perform multisig rotation during lifecycle of a rotation

    Attributes:
        sn (int | None ):  sequence number of est event
        isith (str | list | None):  current signing threshold
        nsith (str | list | None):  next signing threshold
        toad (int | None): threshold of accountable duplicity
        cuts (list | None):  list of backers to remove qb64
        adds (list | None):  list of backers to add qb64
        data (list | None): seals
        date (str | None):  datetime of rotation
        smids (list | None): group signing member identifiers qb64
        rmids (list | None): group signing member identifiers qb64


    ToDo: NRR
    Add mid, midxs tuple (csi, pni)

    """
    sn: int | None  # sequence number of est event
    isith: str | list | None  # current signing threshold
    nsith: str | list | None  # next signing threshold
    toad: int | None  # threshold of accountable duplicity
    cuts: list | None  # list of backers to remove qb64
    adds: list | None  # list of backers to add qb64
    data: list | None  # seals
    date: str | None  # datetime of rotation
    smids: list | None   # group signing member ids
    rmids: list | None = None  # group rotating member ids


@dataclass
class TopicsRecord:  # baser.tops
    """
    Tracks the last message topic index retrieved from the witness mailbox
    Database Key is the identifier prefix of the witness that is storing
    events in a mailbox. (baser.tops)
    """
    topics: dict


@dataclass
class EndpointRecord:  # baser.ends
    """
    Service Endpoint ID (SEID) Record with fields and keys to manage endpoints by
    cid,role, and eid. Serves as aggregation mechanism for authorization and other
    functions such as UX naming with regards the endpoint.

    The namespace is a tree of branches with each leaf at a
    specific (cid, role, eid). Retrieval by branch returns groups of leaves as
    appropriate for a cid braanch or cid.role branch.
    Database Keys are (cid, role, eid) where cid is attributable controller identifier
    (qb64 prefix) that has role(s) such as watcher, witness etc and eid is the
    identifier of the controller acting in a role i.e. watcher identifier.

    Attributes:
        allowed (bool): AuthZ via reply message
                        True means eid is allowed as controller of endpoint in role
                        False means eid is disallowed as conroller of endpint in role
                        None means eid is neither allowed or disallowed (no reply msg)
        enabled (bool): AuthZ via expose message
                        True means eid is enabled as controller of endpoint in role
                        False means eid is disenabled as conroller of endpint in role
                        None means eid is neither enabled or disenabled (no expose msg)
        name (str): user fieldly name for eid in role


    An end authorization reply message is required from which the field values
    for this record are extracted. A routes of /end/role/eid/add  /end/role/eid/cut
    Uses add-cut model with allowed field
    allowed==True eid is allowed (add) as endpoint provider for cid at role and name
    allowed==False eid is disallowed (cut) as endpoint provider for cid at role and name

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rep",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/end/role/add",
      "a" :
      {
         "cid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
         "role": "watcher",  # one of kering.Roles
         "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
      }
    }

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rep",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/end/role/cut",
      "a" :
      {
         "cid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
         "role": "watcher",  # one of kering.Roles
         "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
      }
    }

    An end authorization expose message provides enablement via an exposure of
    and anchored seal to the expose message on the authorizing KEL.


    """
    allowed: bool = None  # True eid allowed (add), False eid disallowed (cut), None neither
    enabled: bool = None  # True eid enabled (add), False eid disenabled (cut), None neither
    name: str = ""  # optional user friendly name of endpoint

    def __iter__(self):
        return iter(asdict(self))


@dataclass
class EndAuthRecord:  # nested as field value in baser.locs
    """
    Service Endpoint Authorization Record provides cross reference field for search
    purposes to find authorization for endpoint provider eid. The default is
    controller id, cid, and a role. used to lookup authorization in end authN
    database with keyspace given by (cid.role.eid) where cid is the authorizing
    controller for the eid (endpoint id) at the given role.
    The cid is usually a transferable identifer with a KEL but may be non-trans.
    The eid is usually a nontransferable identifier when its used for roles
    witness or watcher but may be transferable for other roles such as controller,
    judge, juror, public watcher, or registrar.

    This is an embedded record type in a LocationRecord in the cids field

    """
    cid: str = ""  # identifier prefix of controller that authorizes endpoint
    roles: list[str] = field(default_factory=list)  # str endpoint roles such as watcher, witness etc

    def __iter__(self):
        return iter(asdict(self))


@dataclass
class LocationRecord:  # baser.locs
    """
    Service Endpoint Record with url for endpoint of a given scheme  The eid is
    usually a nontransferable identifier when its used for roles witness or watcher
    but may be transferable for other roles such as controller, judge, juror,
    public watcher, or registrar.

    Database Keys are (eid, scheme) where eid is service endpoint identifier
    (qb64 prefix) and scheme is the url protocol scheme (tcp, https).

    A loc reply message is required from which the values of this
    database record are extracted. route is /loc/scheme Uses enact-anul model
    To nullify endpoint set url field to empty.

    An end authorization reply message is also required to authorize the eid as
    endpoint provider for cid at role. See EndpointRecord

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rep",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/loc/scheme",
      "a" :
      {
         "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
         "scheme": "http",  # one of kering.Schemes
         "url":  "http://localhost:8080/watcher/wilma",
      }
    }

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rep",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/loc/scheme",
      "a" :
      {
         "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
         "scheme": "http",  # one of kering.Schemes
         "url":  "",
      }
    }

    """
    url: str  # full url including host:port/path?query scheme is optional

    # cids: list[EndAuthRecord] = field(default_factory=list)  # optional authorization record references

    def __iter__(self):
        return iter(asdict(self))


@dataclass
class WellKnownAuthN:
    """
    Each WellKnownAuthN represents a successfully resolved .well-known OOBI URL keyed by
    the AID of the OOBI tuple embedded in the URL

    """

    url: str  # full .well-known OOBI URL resolved
    dt: str  # iso8601 date/time of success resolution


def openDB(*, cls=None, name="test", **kwa):
    """
    Returns contextmanager generated by openLMDB but with Baser instance as default
    """
    if cls == None:  # can't reference class before its defined below
        cls = Baser
    return dbing.openLMDB(cls=cls, name=name, **kwa)


@contextmanager
def reopenDB(db, clear=False, **kwa):
    """
    Context manager wrapper LMDB DB instances.
    Repens and closes db.path and db.env LMDB

    Parameters:
        db (LMDBer): instance with LMDB environment at .env
        clear (bool): True means clear directory after close

    Usage:

    with reopenDB(baser) as env:
        env.  ....

    """
    try:
        db.reopen(clear=clear, **kwa)
        yield db.env

    finally:
        db.close(clear=clear)


class Baser(dbing.LMDBer):
    """
    Baser sets up named sub databases with Keri Event Logs within main database

    Attributes:
        see superclass LMDBer for inherited attributes

        kevers (dict): Kever instances indexed by identifier prefix qb64
        prefixes (OrderedSet): local prefixes corresponding to habitats for this db

        .evts is named sub DB whose values are serialized events
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            Only one value per DB key is allowed

        .fels is named sub DB of first seen event log table (FEL) of digests
            that indexes events in first 'seen' accepted order for replay and
            cloning of event log. Only one value per DB key is allowed.
            Provides append only ordering of accepted first seen events.
            Uses first seen order number or fn.
            fnKey
            DB is keyed by identifier prefix plus monotonically increasing first
            seen order number fn.
            Value is digest of serialized event used to lookup event in .evts sub DB

        .dtss is named sub DB of datetime stamp strings in ISO 8601 format of
            the datetime when the event was first escrosed and then later first
            seen by log. Used for escrows timeouts and extended validation.
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            Value is ISO 8601 datetime stamp bytes

        .aess is named sub DB of authorizing event source seal couples
            that map digest to seal source couple of authorizer's
            (delegator or issuer) event. Each couple is a concatenation of full
            qualified items, snu+dig of the authorizing (delegating or issuing)
            source event.
            dgKey
            Values are couples used to lookup authorizer's source event in
            .kels sub DB
            DB is keyed by identifer prefix plus digest of key event
            Only one value per DB key is allowed

        .sigs is named sub DB of fully qualified indexed event signatures
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .wigs is named sub DB of indexed witness signatures of event
            Witnesses always have nontransferable indetifier prefixes.
            The index is the offset of the witness into the witness list
            of the most recent establishment event wrt the receipted event.
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .rcts is named sub DB of event receipt couplets from nontransferable
            signers. Each couple is concatenation of fully qualified items.
            These are: non-transferale prefix plus non-indexed event signature
            by that prefix.
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .ures is named sub DB of unverified event receipt escrowed triples from
            non-transferable signers. Each triple is concatenation of fully
            qualified items. These are: receipted event digest,
            non-transferable receiptor identfier prefix,
            plus nonindexed receipt event signature by that prefix.
            snKey
            DB is keyed by receipted event controller prefix plus sn
            of serialized event
            More than one value per DB key is allowed

        .vrcs is named sub DB of event validator receipt quadruples from transferable
            signers. Each quadruple is concatenation of  four fully qualified items
            of validator. These are: transferable prefix, plus latest establishment
            event sequence number plus latest establishment event digest,
            plus indexed event signature.
            When latest establishment event is multisig then there will
            be multiple quadruples one per signing key, each a dup at same db key.
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .vres is named sub DB of unverified event validator receipt escrowed
            quadruples from transferable signers. Each quadruple is concatenation of
            four fully qualified items  of validator. These are: transferable prefix,
            plus latest establishment event sequence number plus latest
            establishment event digest, plus indexed event signature.
            When latest establishment event is multisig then there will
            be multiple quadruples one per signing key, each a dup at same db key.
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .kels is named sub DB of key event log tables that map sequence numbers
            to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pses is named sub DB of partially signed escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pdes is named sub DB of partially delegated escrowed couples
            that map digest to seal source couple that provides source
            (delegator or issuer) event seal. Each couples is concatenations
            of full qualified items, snu+dig of authorizing (delegating or
            issuing) source event.
            dgKey
            Values are couples used to lookup source event in .kels sub DB
            DB is keyed by identifer prefix plus digest of key event
            Only one value per DB key is allowed

        .pwes is named sub DB of partially witnessed escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .uwes is named sub DB of unverified event indexed escrowed couples from
            witness signers. Witnesses are from witness list of latest establishment
            event for the receipted event. Each couple is concatenation of fully
            qualified items, edig+sig where:
                edig is receipted event digest
                wig is indexed signature of that event with keypair derived from
                    witness nontrans identifier prefix from witness list and index
                    is offset into witness list of latest establishment event for
                    receipted event
            snKey
            DB is keyed by receipted event controller prefix plus sn
            of serialized event
            More than one value per DB key is allowed

        .ooes is named sub DB of out of order escrowed event tables
            that map a prefix and sequence number to a set of serialized event
            digests.
            Values are digests used to lookup event in .evts, .sigs and .dtss
            sub DBs.
            snKey
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .dels is named sub DB of deplicitous event log tables that map sequence numbers
            to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .ldes is named sub DB of likely deplicitous escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .fons is named subDB instance of MatterSuber that maps
            (prefix, digest) e.g. dgKey to fn value (first seen ordinal number) of
            the associated event. So one can lookup event digest, get its fn here
            and then use fn to fetch event by fn from .fels.

        .states (stts) is named subDB instance of SerderSuber that maps a prefix
            to the latest keystate for that prefix. Used by ._kevers.db for read
            through cache of key state to reload kevers in memory

        .habs is named subDB instance of Komer that maps habitat names to habitat
            application state. Includes habitat identifier prefix
            key is habitat name str
            value is serialized HabitatRecord dataclass

        .sdts (sad date-time-stamp) named subDB instance of CesrSuber that
            that maps SAD SAID to Dater instance's CESR serialization of
            ISO-8601 datetime
            key = said (bytes) of sad, val = dater.qb64b

        .ssgs (sad trans indexed sigs) named subDB instance of CesrIoSetSuber
            that maps keys quadruple (saider.qb64, prefixer.qb64, seqner.q64,
            diger.qb64) to val Siger of trans id siganture. Where: saider is
            said of SAD and prefixer, seqner, and diger indicate the key state
            est event for signer or reply SAD. Each key may
            have a set of vals in insertion order one for each signer of the sad.
            key = join (saider.qb64b, prefixer.qb64b, seqner.qb64b, diger.qb64b)
            (bytes)  val = siger.qb64b

        .scgs (sad nontrans cigs) named subDB instance of CatCesrIoSetSuber
            that maps said of SAD to couple (Verfer, Cigar) for nontrans signer.
            For nontrans qb64 of Verfer is same as Prefixer.
            Each key may have a set of vals in insertion order one for each
            nontrans signer of the sad.
            key = said (bytes of SAD, val = cat of (verfer.qb64, cigar.qb64b)

        .rpys (replys) named subDB instance of SerderSuber that maps said of
            reply message (versioned SAD) to serialization of that reply message.
            key is said bytes, val is Serder.raw bytes of reply 'rpy' message

        .rpes (reply escrows) named subDB instance of CesrIoSetSuber that
            maps routes of reply (versioned SAD) to single Saider of that
            reply msg.
            Routes such as '/end/role/' and '/loc/scheme'
            key is route bytes,  vals = saider.qb64b of reply 'rpy' msg

        .eans is named subDB instance of CesrSuber with klas=Saider that maps
            cid.role.eid to said of reply SAD as auth:  authN by controller cid
            of authZ that designates endpoint provider eid in role
            routes /end/role/add and /end/role/cut to nullify
            key is cid.role.eid,  val = saider.qb64b of reply 'rpy' msg SAD

        .lans is named subDB instance of CesrSuber with klas=Saider that maps
            eid.scheme to said of reply SAD as auth: authN by endpoint provider
            eid that designates scheme for url
            route /loc/scheme   use null url to nullify
            key is eid.scheme,  val = saider.qb64b of reply 'rpy' msg SAD

        .ends is named subDB instance of Komer that maps (cid, role, eid)
            to attributes about endpoint authorization where:
            cid is controller prefix, role is endpoint role, watcher etc, and
            eid is controller prefix of endpoint controller watcher etc.
            key is cid.role.eid,  value is serialized EndpointRecord dataclass

        .locs is named subDB instance of Komer that maps endpoint prefix eid
            and endpoint network location scheme to endpoint location details
            key is eid.scheme, val is serialized LocationRecord dataclass

        .tops is named subDB instance of Komer that maps Witness identifier
            prefix to topic index of last received mailbox message.
            key is witness prefix identifier
            value is serialized TopicsRecord dataclass

        .gids is named subDB instance of Komer that maps group identifier prefix
            to the local identifier prefix and list of remote identifier prefixes
            that participate in the group identifier.
            key is group identifier prefix
            value is serialized GroupIdentifier dataclass




    Properties:


    """

    def __init__(self, headDirPath=None, reopen=False, **kwa):
        """
        Setup named sub databases.

        Parameters:
            name is str directory path name differentiator for main database
                When system employs more than one keri database, name allows
                differentiating each instance by name
            temp is boolean, assign to .temp
                True then open in temporary directory, clear on close
                Othewise then open persistent directory, do not clear on close
            headDirPath is optional str head directory pathname for main database
                If not provided use default .HeadDirpath
            mode is int numeric os dir permissions for database directory
            reopen (bool): True means database will be reopened by this init


        """
        self.prefixes = oset()
        self._kevers = dbdict()
        self._kevers.db = self  # assign db for read thorugh cache of kevers

        super(Baser, self).__init__(headDirPath=headDirPath, reopen=reopen, **kwa)

    @property
    def kevers(self):
        """
        Returns .db.kevers
        """
        return self._kevers

    def reopen(self, **kwa):
        """
        Open sub databases

        Notes:

        dupsort=True for sub DB means allow unique (key,pair) duplicates at a key.
        Duplicate means that is more than one value at a key but not a redundant
        copies a (key,value) pair per key. In other words the pair (key,value)
        must be unique both key and value in combination.
        Attempting to put the same (key,value) pair a second time does
        not add another copy.

        Duplicates are inserted in lexocographic order by value, insertion order.

        """
        super(Baser, self).reopen(**kwa)

        # Create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.

        self.evts = self.env.open_db(key=b'evts.')
        self.fels = self.env.open_db(key=b'fels.')
        self.dtss = self.env.open_db(key=b'dtss.')
        self.aess = self.env.open_db(key=b'aess.')
        self.sigs = self.env.open_db(key=b'sigs.', dupsort=True)
        self.wigs = self.env.open_db(key=b'wigs.', dupsort=True)
        self.rcts = self.env.open_db(key=b'rcts.', dupsort=True)
        self.ures = self.env.open_db(key=b'ures.', dupsort=True)
        self.vrcs = self.env.open_db(key=b'vrcs.', dupsort=True)
        self.vres = self.env.open_db(key=b'vres.', dupsort=True)
        self.kels = self.env.open_db(key=b'kels.', dupsort=True)
        self.pses = self.env.open_db(key=b'pses.', dupsort=True)
        self.pdes = self.env.open_db(key=b'pdes.')
        self.pwes = self.env.open_db(key=b'pwes.', dupsort=True)
        self.uwes = self.env.open_db(key=b'uwes.', dupsort=True)
        self.ooes = self.env.open_db(key=b'ooes.', dupsort=True)
        self.dels = self.env.open_db(key=b'dels.', dupsort=True)
        self.ldes = self.env.open_db(key=b'ldes.', dupsort=True)
        self.qnfs = self.env.open_db(key=b'qnfs.', dupsort=True)

        # events as ordered by first seen ordinals
        self.fons = subing.CesrSuber(db=self, subkey='fons.', klas=coring.Seqner)
        # Kever state
        self.states = subing.SerderSuber(db=self, subkey='stts.')  # key states
        self.wits = subing.CesrIoSetSuber(db=self, subkey="wits.", klas=coring.Prefixer)

        # habitat application state keyed by habitat name, includes prefix
        self.habs = koming.Komer(db=self,
                                 subkey='habs.',
                                 schema=HabitatRecord, )

        # SAD support datetime stamps and signatures indexed and not-indexed
        # all sad  sdts (sad datetime serializations) maps said to date-time
        self.sdts = subing.CesrSuber(db=self, subkey='sdts.', klas=coring.Dater)

        # all sad ssgs (sad indexed signature serializations) maps SAD quadkeys
        # given by quadruple (saider.qb64, prefixer.qb64, seqner.q64, diger.qb64)
        #  of reply and trans signer's key state est evt to val Siger for each
        # signature.
        self.ssgs = subing.CesrIoSetSuber(db=self, subkey='ssgs.', klas=coring.Siger)

        # all sad scgs  (sad non-indexed signature serializations) maps SAD SAID
        # to couple (Verfer, Cigar) of nontrans signer of signature in Cigar
        # nontrans qb64 of Prefixer is same as Verfer
        self.scgs = subing.CatCesrIoSetSuber(db=self, subkey='scgs.',
                                             klas=(coring.Verfer, coring.Cigar))

        # all reply messages. Maps reply said to serialization. Replys are
        # versioned sads ( with version string) so use Serder to deserialize and
        # use  .sdts, .ssgs, and .scgs for datetimes and signatures
        self.rpys = subing.SerderSuber(db=self, subkey='rpys.')

        # all reply escrows indices of partially signed reply messages. Maps
        # route in reply to single (Saider,)  of escrowed reply.
        # Routes such as /end/role  /loc/schema
        self.rpes = subing.CesrIoSetSuber(db=self, subkey='rpes.',
                                          klas=coring.Saider)

        # auth AuthN/AuthZ by controller at cid of endpoint provider at eid
        # maps key=cid.role.eid to val=said of end reply
        self.eans = subing.CesrSuber(db=self, subkey='eans.', klas=coring.Saider)

        # auth AuthN/AuthZ by endpoint provider at eid of location at scheme url
        # maps key=cid.role.eid to val=said of end reply
        self.lans = subing.CesrSuber(db=self, subkey='lans.', klas=coring.Saider)

        # service endpoint identifer (eid) auths keyed by controller cid.role.eid
        # data extracted from reply /end/role/add or /end/role/cut
        self.ends = koming.Komer(db=self, subkey='ends.',
                                 schema=EndpointRecord, )

        # service endpont locations keyed by eid.scheme  (endpoint identifier)
        # data extracted from reply loc
        self.locs = koming.Komer(db=self,
                                 subkey='locs.',
                                 schema=LocationRecord, )

        # index of last retrieved message from witness mailbox
        self.tops = koming.Komer(db=self,
                                 subkey='witm.',
                                 schema=TopicsRecord, )

        # group local witness escrow
        self.glwe = koming.Komer(db=self, subkey='glwe.',
                                 schema=RotateRecord)

        # group partial signature escrow
        self.gpae = koming.Komer(db=self, subkey='gpae.',
                                 schema=RotateRecord)

        # group partial signature escrow
        self.gpse = subing.CatCesrIoSetSuber(db=self, subkey='gpse.',
                                             klas=(coring.Seqner, coring.Saider))

        # group delegate escrow
        self.gdee = subing.CatCesrIoSetSuber(db=self, subkey='gdee.',
                                             klas=(coring.Seqner, coring.Saider))

        # group partial witness escrow
        self.gpwe = subing.CatCesrIoSetSuber(db=self, subkey='gdwe.',
                                             klas=(coring.Seqner, coring.Saider))

        # completed group multisig
        self.cgms = subing.CesrSuber(db=self, subkey='cgms.',
                                     klas=coring.Saider)

        # exchange message partial signature escrow
        self.epse = subing.SerderSuber(db=self, subkey="epse.")

        # exchange messages
        self.exns = subing.SerderSuber(db=self, subkey="exns.")

        # exchange messages
        self.sxns = subing.SerderSuber(db=self, subkey="sxns.")

        # exchange message signatures
        self.esigs = subing.CesrIoSetSuber(db=self, subkey='esigs.', klas=coring.Siger)

        # exchange message signatures
        self.ecigs = subing.CesrIoSetSuber(db=self, subkey='ecigs.', klas=coring.Cigar)

        # exchange source prefix
        self.esrc = subing.CesrSuber(db=self, subkey='esrc.', klas=coring.Prefixer)

        # exchange pathed attachments
        self.epath = subing.IoSetSuber(db=self, subkey=".epath")

        # accepted signed 12-word challenge response exn messages keys by prefix of signer
        self.chas = subing.CesrIoSetSuber(db=self, subkey='chas.', klas=coring.Saider)

        # successfull signed 12-word challenge response exn messages keys by prefix of signer
        self.reps = subing.CesrIoSetSuber(db=self, subkey='reps.', klas=coring.Saider)

        # group partial signature escrow
        self.wkas = koming.IoSetKomer(db=self, subkey='wkas.', schema=WellKnownAuthN)

        # KSN support datetime stamps and signatures indexed and not-indexed
        # all ksn  kdts (key state datetime serializations) maps said to date-time
        self.kdts = subing.CesrSuber(db=self, subkey='kdts.', klas=coring.Dater)

        # all key state messages. Maps key state said to serialization. ksns are
        # versioned sads ( with version string) so use Serder to deserialize and
        # use  .kdts, .ksgs, and .kcgs for datetimes and signatures
        self.ksns = subing.SerderSuber(db=self, subkey='ksns.')

        # all key state ksgs (ksn indexed signature serializations) maps ksn quadkeys
        # given by quadruple (saider.qb64, prefixer.qb64, seqner.q64, diger.qb64)
        #  of reply and trans signer's key state est evt to val Siger for each
        # signature.
        self.ksgs = subing.CesrIoSetSuber(db=self, subkey='ksgs.', klas=coring.Siger)

        # all key state kcgs  (ksn non-indexed signature serializations) maps ksn SAID
        # to couple (Verfer, Cigar) of nontrans signer of signature in Cigar
        # nontrans qb64 of Prefixer is same as Verfer
        self.kcgs = subing.CatCesrIoSetSuber(db=self, subkey='kcgs.',
                                             klas=(coring.Verfer, coring.Cigar))

        # all key state escrows indices of partially signed ksn messages. Maps
        # route in reply to single (Saider,)  of escrowed ksn.
        # Routes such as /ksn/{aid}
        self.knes = subing.CesrIoSetSuber(db=self, subkey='knes', klas=coring.Saider)

        # key state SAID database for successfully saved key state notices
        # maps key=(prefix, aid) to val=said of key state
        self.knas = subing.CesrSuber(db=self, subkey='knas.', klas=coring.Saider)

        # config loaded oobis to be processed asynchronously, keyed by oobi URL
        self.oobis = koming.Komer(db=self,
                                  subkey='oobis.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # escrow OOBIs that failed to load, retriable, keyed by oobi URL
        self.eoobi = koming.Komer(db=self,
                                  subkey='eoobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # OOBIs with outstand client requests.
        self.coobi = koming.Komer(db=self,
                                  subkey='coobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Resolved OOBIs (those that have been processed successfully for this database.
        self.roobi = koming.Komer(db=self,
                                  subkey='roobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Well known OOBIs that are to be used for mfa against a resolved OOBI.
        self.woobi = koming.Komer(db=self,
                                  subkey='woobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Well known OOBIs that are to be used for mfa against a resolved OOBI.
        self.moobi = koming.Komer(db=self,
                                  subkey='moobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Multifactor well known OOBI auth records to process.  Keys by controller URL
        self.mfa = koming.Komer(db=self,
                                subkey='mfa.',
                                schema=OobiRecord,
                                sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Resolved multifactor well known OOBI auth records.  Keys by controller URL
        self.rmfa = koming.Komer(db=self,
                                 subkey='mfa.',
                                 schema=OobiRecord,
                                 sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # JSON schema SADs keys by the SAID
        self.schema = subing.SchemerSuber(db=self,
                                          subkey='schema.')

        # Field values for contact information for remote identfiers.  Keyed by prefix/field
        self.cfld = subing.Suber(db=self,
                                 subkey="cfld.")

        # Global settings for the Habery environment
        self.hbys = subing.Suber(db=self, subkey='hbys.')
        # Signed contact data, keys by prefix
        self.cons = subing.Suber(db=self,
                                 subkey="cons.")

        # Transferable signatures on contact data
        self.ccigs = subing.CesrSuber(db=self, subkey='ccigs.', klas=coring.Cigar)
        # Chunked image data for contact information for remote identfiers
        self.imgs = self.env.open_db(key=b'imgs.')

        self.reload()

        return self.env

    def reload(self):
        """
        Reload stored prefixes and Kevers from .habs

        """
        removes = []
        for keys, data in self.habs.getItemIter():
            if (state := self.states.get(keys=data.hid)) is not None:
                try:
                    kever = eventing.Kever(state=state, db=self,
                                           prefixes=self.prefixes,
                                           local=True)
                except kering.MissingEntryError as ex:  # no kel event for keystate
                    removes.append(keys)  # remove from .habs
                    continue
                self.kevers[kever.prefixer.qb64] = kever
                self.prefixes.add(kever.prefixer.qb64)
            elif data.mid is None:  # in .habs but no corresponding key state and not a group so remove
                removes.append(keys)  # no key state or KEL event for .hab record

        for keys in removes:  # remove bare .habs records
            self.habs.rem(keys=keys)

    def clean(self):
        """
        Clean database by creating re-verified cleaned cloned copy
        and then replacing original with cleaned cloned copy

        Database usage should be offline during cleaning as it will be cloned in
        readonly mode

        """
        # create copy to clone into
        with openDB(name=self.name,
                    temp=self.temp,
                    headDirPath=self.headDirPath,
                    perm=self.perm,
                    clean=True) as copy:

            with reopenDB(db=self, reuse=True, readonly=True):  # reopen as readonly
                if not os.path.exists(self.path):
                    raise ValueError("Error while cleaning, no orig at {}."
                                     "".format(self.path))

                kvy = eventing.Kevery(db=copy)  # promiscuous mode

                # Revise in future to NOT parse msgs but to extract the processed
                # objects so can pass directly to kvy.processEvent()
                # need new method cloneObjAllPreIter()
                # process event doesn't capture exceptions so we can more easily
                # detect in the cloning that some events did not make it through
                psr = parsing.Parser(kvy=kvy)
                for msg in self.cloneAllPreIter():  # clone into copy
                    psr.parseOne(ims=msg)

                # clone .habs  habitat name prefix Komer subdb
                # copy.habs = koming.Komer(db=copy, schema=HabitatRecord, subkey='habs.')  # copy
                for keys, val in self.habs.getItemIter():
                    if val.hid in copy.kevers:  # only copy habs that verified
                        copy.habs.put(keys=keys, val=val)
                        copy.prefixes.add(val.hid)

                if not copy.habs.get(keys=(self.name,)):
                    raise ValueError("Error cloning habs, missing orig name={}."
                                     "".format(self.name))

                # clone .ends and .locs databases
                for keys, val in self.ends.getItemIter():
                    exists = False  # only copy if entries in both .ends and .locs
                    for scheme in ("https", "http", "tcp"):  # all supported schemes
                        lval = self.locs.get(keys=(val.eid, scheme))
                        if lval and lval.cid == keys[0] and lval.role == keys[1]:
                            exists = True  # loc with matching cid and rol
                            copy.locs.put(keys=(val.eid, scheme), val=lval)
                    if exists:  # only copy end if has at least one matching loc
                        copy.ends.put(keys=keys, vals=[val])

            # remove own db directory replace with clean clone copy
            if os.path.exists(self.path):
                shutil.rmtree(self.path)

            dst = shutil.move(copy.path, self.path)  # move copy back to orig
            if not dst:  # move failed leave new in place so can manually fix
                raise ValueError("Error cloning, unable to move {} to {}."
                                 "".format(copy.path, self.path))

            # replace own kevers with copy kevers by clear and copy
            # future do this by loading kever from .stts  key state subdb
            self.kevers.clear()
            for pre, kever in copy.kevers.items():
                self.kevers[pre] = kever

            # replace prefixes with cloned copy prefixes

            # clear and clone .prefixes
            self.prefixes.clear()
            self.prefixes.update(copy.prefixes)

            with reopenDB(db=self, reuse=True):  # make sure can reopen
                if not isinstance(self.env, lmdb.Environment):
                    raise ValueError("Error cloning, unable to reopen."
                                     "".format(self.path))

        # clone success so remove if still there
        if os.path.exists(copy.path):
            shutil.rmtree(copy.path)

    def clonePreIter(self, pre, fn=0):
        """
        Returns iterator of first seen event messages with attachments for the
        identifier prefix pre starting at first seen order number, fn.
        Essentially a replay in first seen order with attachments
        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for fn, dig in self.getFelItemPreIter(pre, fn=fn):
            try:
                msg = self.cloneEvtMsg(pre=pre, fn=fn, dig=dig)
            except Exception:
                continue  # skip this event
            yield msg

    def cloneAllPreIter(self, key=b''):
        """
        Returns iterator of first seen event messages with attachments for all
        identifier prefixes starting at key. If key == b'' then rstart at first
        key in databse. Use key to resume replay.
        Essentially a replay in first seen order with attachments of entire
        set of FELs.

        Parameters:
            key (bytes): fnKey(pre, fn)
        """
        for pre, fn, dig in self.getFelItemAllPreIter(key=key):
            try:
                msg = self.cloneEvtMsg(pre=pre, fn=fn, dig=dig)
            except Exception:
                continue  # skip this event
            yield msg

    def cloneEvtMsg(self, pre, fn, dig):
        """
        Clones Event as Serialized CESR Message with Body and attached Foot

        Parameters:
            pre (bytes): identifier prefix of event
            fn (int): first seen number (ordinal) of event
            dig (bytes): digest of event

        Returns:
            bytearray: message body with attachments
        """
        msg = bytearray()  # message
        atc = bytearray()  # attachments
        dgkey = dbing.dgKey(pre, dig)  # get message
        if not (raw := self.getEvt(key=dgkey)):
            raise kering.MissingEntryError("Missing event for dig={}.".format(dig))
        msg.extend(raw)

        # add indexed signatures to attachments
        if not (sigs := self.getSigs(key=dgkey)):
            raise kering.MissingEntryError("Missing sigs for dig={}.".format(dig))
        atc.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=len(sigs)).qb64b)
        for sig in sigs:
            atc.extend(sig)

        # add indexed witness signatures to attachments
        if wigs := self.getWigs(key=dgkey):
            atc.extend(coring.Counter(code=coring.CtrDex.WitnessIdxSigs,
                                      count=len(wigs)).qb64b)
            for wig in wigs:
                atc.extend(wig)

        # add authorizer (delegator/issure) source seal event couple to attachments
        couple = self.getAes(dgkey)
        if couple is not None:
            atc.extend(coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                      count=1).qb64b)
            atc.extend(couple)

        # add trans receipts quadruples to attachments
        if quads := self.getVrcs(key=dgkey):
            atc.extend(coring.Counter(code=coring.CtrDex.TransReceiptQuadruples,
                                      count=len(quads)).qb64b)
            for quad in quads:
                atc.extend(quad)

        # add nontrans receipts couples to attachments
        if coups := self.getRcts(key=dgkey):
            atc.extend(coring.Counter(code=coring.CtrDex.NonTransReceiptCouples,
                                      count=len(coups)).qb64b)
            for coup in coups:
                atc.extend(coup)

        # add first seen replay couple to attachments
        if not (dts := self.getDts(key=dgkey)):
            raise kering.MissingEntryError("Missing datetime for dig={}.".format(dig))
        atc.extend(coring.Counter(code=coring.CtrDex.FirstSeenReplayCouples,
                                  count=1).qb64b)
        atc.extend(coring.Seqner(sn=fn).qb64b)
        atc.extend(coring.Dater(dts=bytes(dts)).qb64b)

        # prepend pipelining counter to attachments
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        pcnt = coring.Counter(code=coring.CtrDex.AttachedMaterialQuadlets,
                              count=(len(atc) // 4)).qb64b
        msg.extend(pcnt)
        msg.extend(atc)
        return msg

    def findAnchoringEvent(self, pre, anchor):
        """
        Search through a KEL for the event that contains a specific anchor.
        Returns the Serder of the first event with the anchor, None if not found

        Parameters:
            pre is qb64 identifier of the KEL to search
            anchor is dict of anchor to find

        """
        for evt in self.clonePreIter(pre=pre):
            srdr = coring.Serder(raw=evt)
            if "a" in srdr.ked:
                ancs = srdr.ked["a"]
                for anc in ancs:
                    spre = anc["i"]
                    ssn = int(anc["s"])
                    sdig = anc["d"]

                    if spre == anchor["i"] and ssn == int(anchor["s"]) \
                            and anchor["d"] == sdig and self.fullyWitnessed(srdr):
                        return srdr

        return None

    def fullyWitnessed(self, serder):
        """ Verify the witness threshold on the event

        Parameters:
            serder (Serder): event serder to validate witness threshold

        Returns:

        """
        # Verify fully receipted, because this witness may have persisted before all receipts
        # have been gathered if this ius a witness for serder.pre
        dgkey = dbing.dgKey(serder.preb, serder.saidb)

        # get unique verified wigers and windices lists from wigers list
        wigs = self.getWigs(key=dgkey)
        kever = self.kevers[serder.pre]
        toad = kever.toader.num

        return not len(wigs) < toad

    def resolveVerifiers(self, pre=None, sn=0, dig=None):
        """
        Returns the Tholder and Verfers for the provided identifier prefix.
        Default pre is own .pre

        Parameters:
            pre(str) is qb64 str of bytes of identifier prefix.
            sn(int) is the sequence number of the est event
            dig(str) is qb64 str of digest of est event

        """

        prefixer = coring.Prefixer(qb64=pre)
        if prefixer.transferable:
            # receipted event and receipter in database so get receipter est evt
            # retrieve dig of last event at sn of est evt of receipter.
            sdig = self.getKeLast(key=dbing.snKey(pre=prefixer.qb64b,
                                                  sn=sn))
            if sdig is None:
                # receipter's est event not yet in receipters's KEL
                raise kering.ValidationError("key event sn {} for pre {} is not yet in KEL"
                                             "".format(sn, pre))
            # retrieve last event itself of receipter est evt from sdig
            sraw = self.getEvt(key=dbing.dgKey(pre=prefixer.qb64b, dig=bytes(sdig)))
            # assumes db ensures that sraw must not be none because sdig was in KE
            sserder = coring.Serder(raw=bytes(sraw))
            if dig is not None and not sserder.compare(said=dig):  # endorser's dig not match event
                raise kering.ValidationError("Bad proof sig group at sn = {}"
                                             " for ksn = {}."
                                             "".format(sn, sserder.ked))

            verfers = sserder.verfers
            tholder = sserder.tholder

        else:
            verfers = [coring.Verfer(qb64=pre)]
            tholder = coring.Tholder(sith="1")

        return tholder, verfers

    def putEvt(self, key, val):
        """
        Use dgKey()
        Write serialized event bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.evts, key, val)

    def setEvt(self, key, val):
        """
        Use dgKey()
        Write serialized event bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.evts, key, val)

    def getEvt(self, key):
        """
        Use dgKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.evts, key)

    def delEvt(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.evts, key)

    def putFe(self, key, val):
        """
        Use fnKey()
        Write event digest bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.fels, key, val)

    def setFe(self, key, val):
        """
        Use fnKey()
        Write event digest bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.fels, key, val)

    def getFe(self, key):
        """
        Use fnKey()
        Return event digest at key
        Returns None if no entry at key
        """
        return self.getVal(self.fels, key)

    def delFe(self, key):
        """
        Use snKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.fels, key)

    def appendFe(self, pre, val):
        """
        Return first seen order number int, fn, of appended entry.
        Computes fn as next fn after last entry.
        Uses fnKey(pre, fn) for entries.

        Append val to end of db entries with same pre but with fn incremented by
        1 relative to last preexisting entry at pre.

        Parameters:
            pre is bytes identifier prefix for event
            val is event digest
        """
        return self.appendOrdValPre(db=self.fels, pre=pre, val=val)

    def getFelItemPreIter(self, pre, fn=0):
        """
        Returns iterator of all (fn, dig) duples in first seen order for all events
        with same prefix, pre, in database. Items are sorted by fnKey(pre, fn)
        where fn is first seen order number int.
        Returns a First Seen Event Log FEL.
        Returned items are duples of (fn, dig): Where fn is first seen order
        number int and dig is event digest for lookup in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            pre is bytes of itdentifier prefix
            fn is int fn to resume replay. Earliset is fn=0
        """
        return self.getAllOrdItemPreIter(db=self.fels, pre=pre, on=fn)

    def getFelItemAllPreIter(self, key=b''):
        """
        Returns iterator of all (pre, fn, dig) triples in first seen order for
        all events for all prefixes in database. Items are sorted by
        fnKey(pre, fn) where fn is first seen order number int.
        Returns all First Seen Event Logs FELs.
        Returned items are tripes of (pre, fn, dig): Where pre is identifier prefix,
        fn is first seen order number int and dig is event digest for lookup
        in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            key is key location in db to resume replay, If empty then start at
                first key in database
        """
        return self.getAllOrdItemAllPreIter(db=self.fels, key=key)

    def putDts(self, key, val):
        """
        Use dgKey()
        Write serialized event datetime stamp val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Returns False if key already exists
        """
        return self.putVal(self.dtss, key, val)

    def setDts(self, key, val):
        """
        Use dgKey()
        Write serialized event datetime stamp val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.dtss, key, val)

    def getDts(self, key):
        """
        Use dgKey()
        Return datetime stamp at key
        Returns None if no entry at key
        """
        return self.getVal(self.dtss, key)

    def delDts(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.dtss, key)

    def putAes(self, key, val):
        """
        Use dgKey()
        Write serialized source seal event couple val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Returns False if key already exists
        """
        return self.putVal(self.aess, key, val)

    def setAes(self, key, val):
        """
        Use dgKey()
        Write serialized source seal event couple val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.aess, key, val)

    def getAes(self, key):
        """
        Use dgKey()
        Return source seal event couple at key
        Returns None if no entry at key
        """
        return self.getVal(self.aess, key)

    def delAes(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.aess, key)

    def getSigs(self, key):
        """
        Use dgKey()
        Return list of signatures at key
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.sigs, key)

    def getSigsIter(self, key):
        """
        Use dgKey()
        Return iterator of signatures at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.sigs, key)

    def putSigs(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes signatures vals to key
        Adds to existing signatures at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.sigs, key, vals)

    def addSig(self, key, val):
        """
        Use dgKey()
        Add signature val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.sigs, key, val)

    def cntSigs(self, key):
        """
        Use dgKey()
        Return count of signatures at key
        Returns zero if no entry at key
        """
        return self.cntVals(self.sigs, key)

    def delSigs(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.sigs, key, val)

    def getWigs(self, key):
        """
        Use dgKey()
        Return list of indexed witness signatures at key
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.wigs, key)

    def getWigsIter(self, key):
        """
        Use dgKey()
        Return iterator of indexed witness signatures at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.wigs, key)

    def putWigs(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes indexed witness signatures vals to key
        Adds to existing signatures at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.wigs, key, vals)

    def addWig(self, key, val):
        """
        Use dgKey()
        Add indexed witness signature val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.wigs, key, val)

    def cntWigs(self, key):
        """
        Use dgKey()
        Return count of indexed witness signatures at key
        Returns zero if no entry at key
        """
        return self.cntVals(self.wigs, key)

    def delWigs(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.wigs, key, val)

    def putRcts(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes receipt couplets vals to key
        Couple is pre+cig (non indexed signature)
        Adds to existing receipts at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.rcts, key, vals)

    def addRct(self, key, val):
        """
        Use dgKey()
        Add receipt couple val bytes as dup to key in db
        Couple is pre+cig (non indexed signature)
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.rcts, key, val)

    def getRcts(self, key):
        """
        Use dgKey()
        Return list of receipt couplets at key
        Couple is pre+cig (non indexed signature)
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.rcts, key)

    def getRctsIter(self, key):
        """
        Use dgKey()
        Return iterator of receipt couplets at key
        Couple is pre+cig (non indexed signature)
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.rcts, key)

    def cntRcts(self, key):
        """
        Use dgKey()
        Return count of receipt couplets at key
        Couple is pre+cig (non indexed signature)
        Returns zero if no entry at key
        """
        return self.cntVals(self.rcts, key)

    def delRcts(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.rcts, key, val)

    def putUres(self, key, vals):
        """
        Use snKey()
        Write each entry from list of bytes receipt triples vals to key
        Triple is dig+pre+cig
        Adds to existing receipts at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.ures, key, vals)

    def addUre(self, key, val):
        """
        Use snKey()
        Add receipt triple val bytes as dup to key in db
        Triple is dig+pre+cig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.ures, key, val)

    def getUres(self, key):
        """
        Use snKey()
        Return list of receipt triplets at key
        Triple is dig+pre+cig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.ures, key)

    def getUresIter(self, key):
        """
        Use snKey()
        Return iterator of receipt triplets at key
        Triple is dig+pre+cig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.ures, key)

    def getUreLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event triple val at key
        Triple is dig+pre+cig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.ures, key)

    def getUreItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial signed escrowed event triple items at next
        key after key.
        Item is (key, val) where proem has already been stripped from val
        val is triple dig+pre+cig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.ures, key, skip)

    def getUreItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event triple items at next
        key after key.
        Items is (key, val) where proem has already been stripped from val
        val is triple dig+pre+cig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.ures, key, skip)

    def cntUres(self, key):
        """
        Use snKey()
        Return count of receipt triplets at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.ures, key)

    def delUres(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.ures, key)

    def delUre(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.ures, key, val)

    def putVrcs(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes receipt quadruples vals to key
        quadruple is spre+ssnu+sdig+sig
        Adds to existing receipts at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.vrcs, key, vals)

    def addVrc(self, key, val):
        """
        Use dgKey()
        Add receipt quadruple val bytes as dup to key in db
        quadruple is spre+ssnu+sdig+sig
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.vrcs, key, val)

    def getVrcs(self, key):
        """
        Use dgKey()
        Return list of receipt quadruples at key
        quadruple is spre+ssnu+sdig+sig
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.vrcs, key)

    def getVrcsIter(self, key):
        """
        Use dgKey()
        Return iterator of receipt quadruples at key
        quadruple is spre+ssnu+sdig+sig
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.vrcs, key)

    def cntVrcs(self, key):
        """
        Use dgKey()
        Return count of receipt quadruples at key
        Returns zero if no entry at key
        """
        return self.cntVals(self.vrcs, key)

    def delVrcs(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.vrcs, key, val)

    def putVres(self, key, vals):
        """
        Use snKey()
        Write each entry from list of bytes receipt quinlets vals to key
        Quinlet is edig + spre + ssnu + sdig +sig
        Adds to existing receipts at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.vres, key, vals)

    def addVre(self, key, val):
        """
        Use snKey()
        Add receipt quintuple val bytes as dup to key in db
        Quinlet is edig + spre + ssnu + sdig +sig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.vres, key, val)

    def getVres(self, key):
        """
        Use snKey()
        Return list of receipt quinlets at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.vres, key)

    def getVresIter(self, key):
        """
        Use snKey()
        Return iterator of receipt quinlets at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.vres, key)

    def getVreLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event quintuple val at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.vres, key)

    def getVreItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial signed escrowed event quintuple items at next
        key after key.
        Item is (key, val) where proem has already been stripped from val
        val is Quinlet is edig + spre + ssnu + sdig +sig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.vres, key, skip)

    def getVreItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event quintuple items at next
        key after key.
        Items is (key, val) where proem has already been stripped from val
        val is Quinlet is edig + spre + ssnu + sdig +sig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.vres, key, skip)

    def cntVres(self, key):
        """
        Use snKey()
        Return count of receipt quinlets at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.vres, key)

    def delVres(self, key):
        """
         Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.vres, key)

    def delVre(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.vres, key, val)

    def putKes(self, key, vals):
        """
        Use snKey()
        Write each key event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.kels, key, vals)

    def addKe(self, key, val):
        """
        Use snKey()
        Add key event val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.kels, key, val)

    def getKes(self, key):
        """
        Use snKey()
        Return list of key event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.kels, key)

    def getKeLast(self, key):
        """
        Use snKey()
        Return last inserted dup key event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.kels, key)

    def cntKes(self, key):
        """
        Use snKey()
        Return count of dup key event dig val at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.kels, key)

    def delKes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.kels, key)

    def getKelIter(self, pre):
        """
        Returns iterator of all dup vals in insertion order for all entries
        with same prefix across all sequence numbers without gaps. Stops if
        encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
        db is opened as named sub db with dupsort=True

        Parameters:
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getIoValsAllPreIter(self.kels, pre)

    def getKelBackIter(self, pre, fn):
        """
        Returns iterator of all dup vals in insertion order for all entries
        with same prefix across all sequence numbers without gaps in decreasing
        order starting with first sequence number fn. Stops if encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
        db is opened as named sub db with dupsort=True

        Parameters:
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getIoValsAllPreBackIter(self.kels, pre, fn)

    def getKelEstIter(self, pre):
        """
        Returns iterator of last one of dup vals at each key in insertion order
        for all entries with same prefix across all sequence numbers without gaps.
        Stops if encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
        db is opened as named sub db with dupsort=True

        Parameters:
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getIoValLastAllPreIter(self.kels, pre)

    def putPses(self, key, vals):
        """
        Use snKey()
        Write each partial signed escrow event entry from list of bytes dig vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.pses, key, vals)

    def addPse(self, key, val):
        """
        Use snKey()
        Add Partial signed escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.pses, key, val)

    def getPses(self, key):
        """
        Use snKey()
        Return list of partial signed escrowed event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.pses, key)

    def getPsesIter(self, key):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event dig vals at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.pses, key)

    def getPseLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event dig val at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.pses, key)

    def getPseItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial signed escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.pses, key, skip)

    def getPseItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.pses, key, skip)

    def cntPses(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.pses, key)

    def delPses(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key  exists in db Else False
        """
        return self.delIoVals(self.pses, key)

    def delPse(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.pses, key, val)

    def putPde(self, key, val):
        """
        Use dgKey()
        Write serialized event source couple to key (snu+dig)
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Returns False if key already exists
        """
        return self.putVal(self.pdes, key, val)

    def setPde(self, key, val):
        """
        Use dgKey()
        Write serialized seal source couple to key (snu+dig)
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.pdes, key, val)

    def getPde(self, key):
        """
        Use dgKey()
        Return seal source couple at key
        Returns None if no entry at key
        """
        return self.getVal(self.pdes, key)

    def delPde(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.pdes, key)

    def putPwes(self, key, vals):
        """
        Use snKey()
        Write each partial witnessed escrow event entry from list of bytes dig vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.pwes, key, vals)

    def addPwe(self, key, val):
        """
        Use snKey()
        Add Partial witnessed escrow dig val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.pwes, key, val)

    def getPwes(self, key):
        """
        Use snKey()
        Return list of witnessed signed escrowed event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.pwes, key)

    def getPwesIter(self, key):
        """
        Use sgKey()
        Return iterator of partial witnessed escrowed event dig vals at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.pwes, key)

    def getPweLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial witnessed escrowed event dig val at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.pwes, key)

    def getPweItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial witnessed escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.pwes, key, skip)

    def getPweItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial witnessed escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.pwes, key, skip)

    def cntPwes(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.pwes, key)

    def delPwes(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key  exists in db Else False
        """
        return self.delIoVals(self.pwes, key)

    def delPwe(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.pwes, key, val)

    def putUwes(self, key, vals):
        """
        Use snKey()
        Write each entry from list of bytes witness receipt couples vals to key
        Witness couple is edig+wig
        Adds to existing receipts at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.uwes, key, vals)

    def addUwe(self, key, val):
        """
        Use snKey()
        Add receipt couple val bytes as dup to key in db
        Witness couple is edig+wig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.uwes, key, val)

    def getUwes(self, key):
        """
        Use snKey()
        Return list of receipt couples at key
        Witness couple is edig+wig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.uwes, key)

    def getUwesIter(self, key):
        """
        Use snKey()
        Return iterator of receipt couples at key
        Witness couple is edig+wig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.uwes, key)

    def getUweLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed receipt couple val at key
        Witness couple is edig+wig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.uwes, key)

    def getUweItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial signed escrowed receipt couple items at next
        key after key.
        Item is (key, val) where proem has already been stripped from val
        val is couple edig+wig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.uwes, key, skip)

    def getUweItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial signed escrowed receipt couple items at next
        key after key.
        Items is (key, val) where proem has already been stripped from val
        val is couple edig+wig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.uwes, key, skip)

    def cntUwes(self, key):
        """
        Use snKey()
        Return count of receipt couples at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.uwes, key)

    def delUwes(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.uwes, key)

    def delUwe(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.uwes, key, val)

    def putOoes(self, key, vals):
        """
        Use snKey()
        Write each out of order escrow event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.ooes, key, vals)

    def addOoe(self, key, val):
        """
        Use snKey()
        Add out of order escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.ooes, key, val)

    def getOoes(self, key):
        """
        Use snKey()
        Return list of out of order escrow event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.ooes, key)

    def getOoeLast(self, key):
        """
        Use snKey()
        Return last inserted dup val of out of order escrow event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.ooes, key)

    def getOoeItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of out of order escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.ooes, key, skip)

    def getOoeItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of out of order escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.ooes, key, skip)

    def cntOoes(self, key):
        """
        Use snKey()
        Return count of dup event dig at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.ooes, key)

    def delOoes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.ooes, key)

    def delOoe(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.ooes, key, val)

    def putQnfs(self, key, vals):
        """
        Use snKey()
        Write each out of order escrow event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.qnfs, key, vals)

    def addQnf(self, key, val):
        """
        Use snKey()
        Add out of order escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.qnfs, key, val)

    def getQnfs(self, key):
        """
        Use snKey()
        Return list of out of order escrow event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.qnfs, key)

    def getQnfLast(self, key):
        """
        Use snKey()
        Return last inserted dup val of out of order escrow event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.qnfs, key)

    def getQnfItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of out of order escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.qnfs, key, skip)

    def getQnfItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of out of order escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.qnfs, key, skip)

    def cntQnfs(self, key):
        """
        Use snKey()
        Return count of dup event dig at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.qnfs, key)

    def delQnfs(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.qnfs, key)

    def delQnf(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.qnfs, key, val)

    def putDes(self, key, vals):
        """
        Use snKey()
        Write each duplicitous event entry dig from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.dels, key, vals)

    def addDe(self, key, val):
        """
        Use snKey()
        Add duplicate event index val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.dels, key, val)

    def getDes(self, key):
        """
        Use snKey()
        Return list of duplicitous event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.dels, key)

    def getDeLast(self, key):
        """
        Use snKey()
        Return last inserted dup value of duplicitous event dig vals at key
        Returns None if no entry at key

        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.dels, key)

    def cntDes(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.dels, key)

    def delDes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.dels, key)

    def getDelIter(self, pre):
        """
        Returns iterator of all dup vals  in insertion order for any entries
        with same prefix across all sequence numbers including gaps.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getIoValsAnyPreIter(self.dels, pre)

    def putLdes(self, key, vals):
        """
        Use snKey()
        Write each likely duplicitous event entry dig from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.ldes, key, vals)

    def addLde(self, key, val):
        """
        Use snKey()
        Add likely duplicitous escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.ldes, key, val)

    def getLdes(self, key):
        """
        Use snKey()
        Return list of likely duplicitous event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.ldes, key)

    def getLdeLast(self, key):
        """
        Use snKey()
        Return last inserted dup val of likely duplicitous event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.ldes, key)

    def getLdeItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of likely duplicitous escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.ldes, key, skip)

    def getLdeItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of likely duplicitous escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.ldes, key, skip)

    def cntLdes(self, key):
        """
        Use snKey()
        Return count of dup event dig at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.ldes, key)

    def delLdes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.ldes, key)

    def delLde(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.ldes, key, val)


class BaserDoer(doing.Doer):
    """
    Basic Baser Doer ( LMDB Database )

    Attributes:  (inherited)
        done (bool): completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.

    Attributes:
        .baser is Baser or LMDBer subclass

    Properties:  (inherited)
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

    def __init__(self, baser, **kwa):
        """
        Inherited Parameters:
           tymist is Tymist instance
           tock is float seconds initial value of .tock

        Parameters:
           baser is Baser instance
        """
        super(BaserDoer, self).__init__(**kwa)
        self.baser = baser

    def enter(self):
        """"""
        if not self.baser.opened:
            self.baser.reopen()

    def exit(self):
        """"""
        self.baser.close(clear=self.baser.temp)
