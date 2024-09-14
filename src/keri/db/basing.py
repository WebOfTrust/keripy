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
import importlib
import os
import shutil
from collections import namedtuple
from contextlib import contextmanager
from dataclasses import dataclass, asdict, field
import json


import cbor2 as cbor
import msgpack
import lmdb
import semver
from ordered_set import OrderedSet as oset

from hio.base import doing

import keri
from . import dbing, koming, subing
from .. import kering
from .. import core
from ..core import coring, eventing, parsing, serdering, indexing

from .. import help
from ..help import helping


logger = help.ogler.getLogger()


MIGRATIONS = [
    ("1.1.0", ["rekey_habs"])
]


# ToDo XXXX maybe
'''
class komerdict(dict):
    """
    Subclass of dict that has db as attribute and employs read through cache
    from db Baser.stts of kever states to reload kever from state in database
    when not found in memory as dict item.

    add method that answers is a given pre a group hab pre .localGroup(pre)

    ToDo XXXX change name of dbdict to stateDict since now have differen types
    and can't subclass dict with init parameters.
    but can change function by manually assigning attributes but that is ugly
    need wrapper decorator to do that. So can update attributes with wrapper
    on class that injects instance attributes when class is instanced
    one of the injected parameters is function that that maps returned Komer to
    object class
    parameters are subdb (must be Komer) and function that maps retrieved dataclass
    record  from dataabase to class instance. if no mapping function then just
    return the dataclass record as value.
    """

'''


# ToDo XXXX change name to statedict since not a generic dbdict
class dbdict(dict):
    """
    Subclass of dict that has db as attribute and employs read through cache
    from db Baser.stts of kever states to reload kever from state in database
    when not found in memory as dict item.
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
            if (ksr := self.db.states.get(keys=k)) is None:
                raise ex  # reraise KeyError
            try:
                kever = eventing.Kever(state=ksr, db=self.db)
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
        """Override of dict get method

        Parameters:
            k (str): key for dict
            default: default value to return if not found

        Returns:
            kever: converted from underlying dict or database

        """
        if not super(dbdict, self).__contains__(k):
            return default
        else:
            return self.__getitem__(k)





@dataclass
class RawRecord:
    """RawRecord is base class for dataclasses that provides private utility
    methods for representing the dataclass as some other format like dict,
    json bytes, cbor bytes, mgpk bytes as a raw format. Typically uses case
    is to transform dataclass into dict or serialization of its transformation
    into dict so that it can be included in messages or stored in a database.
    """

    @classmethod
    def _fromdict(cls, d: dict):
        """returns instance of clas initialized from dict d """
        return helping.datify(cls, d)


    def __iter__(self):
        return iter(asdict(self))


    def _asdict(self):
        """Returns dict version of record"""
        return helping.dictify(self)


    def _asjson(self):
        """Returns json bytes version of record"""
        return json.dumps(self._asdict(),
                          separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")


    def _ascbor(self):
        """Returns cbor bytes version of record"""
        return cbor.dumps(self._asdict())


    def _asmgpk(self):
        """Returns mgpk bytes version of record"""
        return msgpack.dumps(self._asdict())


@dataclass
class StateEERecord(RawRecord):
    """
    Corresponds to StateEstEvent namedtuple used as sub record in KeyStateRecord
    for latest establishment event associated with current key state

    Attributes:
        s (str): sequence number of latest est evt lowercase hex no leading zeros
        d (str): SAID qb64  of latest est evt
        br (list[str]): backer aids qb64 remove list (cuts) from latest est event
        ba (list[str]): backer aids qb64 add list (adds) from latest est event
    """
    s: str ='0'  # sequence number of latest event in KEL as hex str
    d: str =''  # latest event digest qb64
    br: list = field(default_factory=list)  # backer AID qb64 remove (cut) list
    ba: list = field(default_factory=list)  # backer AID qb64 add list


@dataclass
class KeyStateRecord(RawRecord):  # baser.state
    """
    Key State information keyed by Identifier Prefix of associated KEL.
    For local AIDs that correspond to Habs this is the Hab AID.
    (see baser.state at 'stts')

    Attributes:
        vn (list[int]): version number [major, minor]
        i (str): identifier prefix qb64
        s (str): sequence number of latest event in KEL as hex str
        p (str): prior event digest qb64
        d (str): latest event digest qb64
        f (str): first seen ordinal number of latest event in KEL as hex str
        dt (str): datetime iso-8601 of key state record update, usually now
        et (str): latest event packet type
        kt (str): signing threshold sith
        k (list[str]): signing keys qb64
        nt (str): next prerotated threshold sith
        n (list[str]): pre-rotation keys qb64
        bt (str): backer threshold hex num
        b (list[str]): backer aids qb64
        c (list[str]): config traits
        ee (StateEERecord): instance
            corresponds to StateEstEvent namedtuple
                s = sn of latest est event as lowercase hex string  no leading zeros,
                d = SAID digest qb64  of latest establishment event
                br = backer (witness) remove list (cuts) from latest est event
                ba = backer (witness) add list (adds) from latest est event
        di (str): delegator aid qb64 or empty str if not delegated

    Note: the seal anchor dict 'a' field is not included in the state notice
    because it may be verbose and would impede the main purpose of a notic which
    is to trigger the download of the latest events, which would include the
    anchored seals.

    """
    vn: list[int] = field(default_factory=list)  # version number [major, minor] round trip serializable
    i: str =''  # identifier prefix qb64
    s: str ='0'  # sequence number of latest event in KEL as hex str
    p: str =''  # prior event digest qb64
    d: str =''  # latest event digest qb64
    f: str ='0'  # first seen ordinal number of latest event in KEL as hex str
    dt: str = ''  # datetime of creation of state
    et: str = ''  # latest evt packet type (ilk)
    kt: str = '0'  # signing threshold sith
    k: list[str] = field(default_factory=list)  # signing key list qb64
    nt: str =  '0'  # next rotation threshold nsith
    n: list[str] =  field(default_factory=list) #  next rotation key digest list qb64
    bt: str = '0'  # backer threshold hex num str
    b: list = field(default_factory=list)  # backer AID list qb64
    c: list[str] =  field(default_factory=list)  # config trait list
    ee: StateEERecord = field(default_factory=StateEERecord)
    di: str = '' # delegator aid qb64 if any otherwise empty '' str


@dataclass
class EventSourceRecord:  # tracks source of event local or remote
    """
    Keyed by dig (said) of serder of event

    Usage:

    """
    local: bool = True  # True of local (protected) else False for remote (unprotected)

    def __iter__(self):
        return iter(asdict(self))


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


    """
    hid: str  # hab own identifier prefix qb64
    name: str | None = None
    domain: str | None = None
    mid: str | None = None  # group member identifier qb64 when hid is group
    smids: list | None = None  # group signing member ids when hid is group
    rmids: list | None = None  # group rotating member ids when hid is group
    sid: str | None = None  # Signify identifier qb64 when hid is Signify
    watchers: list[str] = field(default_factory=list)  # id prefixes qb64 of watchers


@dataclass
class TopicsRecord:  # baser.tops
    """
    Tracks the last message topic index retrieved from the witness mailbox
    Database Key is the identifier prefix of the witness that is storing
    events in a mailbox. (baser.tops)
    """
    topics: dict


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
    The cid is usually a transferable identifier with a KEL but may be non-trans.
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
class ObservedRecord:  # baser.obvs
    """
    Watched Record with fields and keys to manage OIDs (Observed IDs) being watched by a watcher, keyed by
    cid (controller ID), aid (watcher ID), and oid (observed ID).

    The namespace is a tree of branches with each leaf at a
    specific (cid, aid, oid). Retrieval by branch returns groups of leaves as
    appropriate for a cid braanch or cid.aid branch.
    Database Keys are (cid, aid, oid) where cid is attributable controller identifier
    (qb64 prefix).

    Attributes:
        enabled (bool): AuthZ via expose message
                        True means oid is enabled as being observed
                        False means eid is disenabled being observed
                        None means eid is neither enabled or disenabled
        name (str): user friendly name for eid in role
        datetime (str): Date time this record was last observed


    A watcher end reply message is required from which the field values
    for this record are extracted. A routes of /watcher/{aid}/add  /watcher/{aid}/cut
    Uses add-cut model with allowed field
    enabled==True oid is allowed (add) as being observed
    enabled==False oid is disallowed (cut) as being observed

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rpy",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/watcher/BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE/add",
      "a" :
      {
         "cid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
         "oid": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
         "oobi": "http://example.com/oobi/EyX-zd8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      }
    }

    """
    enabled: bool = None  # True eid enabled (add), False eid disenabled (cut), None neither
    name: str = ""  # optional user friendly name of endpoint
    datetime: str = None

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


KERIBaserMapSizeKey = "KERI_BASER_MAP_SIZE"


class Baser(dbing.LMDBer):
    """
    Baser sets up named sub databases with Keri Event Logs within main database

    Attributes:
        see superclass LMDBer for inherited attributes

        kevers (dict): Kever instances indexed by identifier prefix qb64
        prefixes (OrderedSet): local prefixes corresponding to habitats for this db

        .evts is named sub DB whose values are serialized key events
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            Only one value per DB key is allowed

        .kels is named sub DB of key event logs as indices that map sequence numbers
            to serialized key event digests.
            Actual serialized key events are stored in .evts by SAID digest
            Uses sequence number or sn.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            More than one value per DB key is allowed

        .fels is named sub DB of first seen event logs (FEL) as indices that map
            first seen ordinal number to digests.
            Actual serialized key events are stored in .evts by SAID digest
            This indexes events in first 'seen' accepted order for replay and
            cloning of event log.
            Uses first seen order number or fn.
            fnKey
            DB is keyed by identifier prefix plus monotonically increasing first
            seen order number fn.
            Value is digest of serialized event used to lookup event in .evts sub DB
            Only one value per DB key is allowed.
            Provides append only ordering of accepted first seen events.

        .fons is named subDB CesrSuber
            Uses digest
            dgKey
            Maps prefix and digest to fn value (first seen ordinal number) of
            the associated event. So one used pre and event digest, get its fn here
            and then use fn to fetch event from .evnts by fn from .fels.
            This ensures that any event looked up this way was first seen at
            some point in time even if later superseded by a recovery rotation.
            Whereas direct lookup in .evts could be escrowed events that may
            never have been accepted as first seen.
            CesrSuber(db=self, subkey='fons.', klas=core.Number)

        .esrs is named sub DB instance of Komer of EventSourceRecord
            dgKey
            DB is keyed by identifier prefix plus digest (said) of serialized event
            Value is serialized instance of EventSourceRecord dataclass.
            Only one value per DB key is allowed.
            Keeps track of the source of the event. When .local is Truthy the
            event was sourced in a protected way such as being generated
            locally or via a protected path. When .local is Falsey the event was
            NOT sourced in a protected way. The value of .local determines what
            validation logic to run on the event. This database is used to track
            the source when processing escrows that would otherwise be decoupled
            from the original source of the event.

        .misfits is named sub DB instance of CesrIoSetSuber for misfit escrows
            subkey "mfes."
            snKey
            DB is keyed by event controller prefix plus sn of serialized event
            where sn is 32 char hex string with leading zeros
            Value is serialized qb64b dig (said) of event
            Misfit escrows are events with remote (nonlocal) sources that are
            inappropriate (i.e. would be dropped) unless they can be promoted
            to local source via some extra after the fact authentication.
            Escrow processing determines if and how to promote event source to
            local and then reprocess

        .delegables is named sub DB instance of CesrIoSetSuber for delegable event
            escrows of key event with local delegator that need approval.
            subkey "dees."  delegable event escrows
            snKey
            DB is keyed by event controller prefix plus sn of serialized event
            where sn is 32 char hex string with leading zeros
            Value is serialized qb64b dig (said) of event
            Delegable event escrows are events with local delegator that need
            to be approved via the anchoring of the delegated event seal in
            the delegator's KEL. Event source must be local. A nonlocal (remote)
            source for a delegable event of a local delegator must first pass
            through the misfit escrow and get promoted to local source.


        .dtss is named sub DB of datetime stamp strings in ISO 8601 format of
            the datetime when the event was first escrosed and then later first
            seen by log. Used for escrows timeouts and extended validation.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            Value is ISO 8601 datetime stamp bytes

        .aess is named sub DB of authorizing event source seal couples
            that map digest to seal source couple of authorizer's
            (delegator or issuer) event. Each couple is a concatenation of full
            qualified items, snu+dig of the authorizing (delegating or issuing)
            source event.
            dgKey
            Values are couples used to lookup authorizer's source event in
            .kels sub DB
            DB is keyed by identifier prefix plus digest of key event
            Only one value per DB key is allowed

        .sigs is named sub DB of fully qualified indexed event signatures
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed

        .wigs is named sub DB of indexed witness signatures of event that may
            come directly or derived from a witness receipt message.
            Witnesses always have nontransferable identifier prefixes.
            The index is the offset of the witness into the witness list
            of the most recent establishment event wrt the receipted event.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed

        .rcts is named sub DB of event receipt couplets from nontransferable
            signers.
            These are endorsements from nontrasferable signers who are not witnesses
            May be watchers or other
            Each couple is concatenation of fully qualified items.
            These are: non-transferale prefix plus non-indexed event signature
            by that prefix.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed

        .ures is named sub DB of unverified event receipt escrowed triples from
            non-transferable signers. Each triple is concatenation of fully
            qualified items. These are: receipted event digest,
            non-transferable receiptor identifier prefix,
            plus nonindexed receipt event signature by that prefix.
             Used to manage out of order events such as escrowing
            receipt couple until event receipted shows up.
            snKey
            DB is keyed by receipted event controller prefix plus sn
            of serialized event
            More than one value per DB key is allowed

        .vrcs is named sub DB of event validator receipt quadruples from transferable
            signers. Each quadruple is concatenation of  four fully qualified items
            of validator. These are: transferable prefix, plus latest establishment
            event sequence number plus latest establishment event digest,
            plus indexed event signature.
            These are endorsements by transferable AIDs that are not the controller
            may be watchers or others.
            When latest establishment event is multisig then there will
            be multiple quadruples one per signing key, each a dup at same db key.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed

        .vres is named sub DB of unverified event validator receipt escrowed
            quadruples from transferable signers. Each quadruple is concatenation of
            four fully qualified items  of validator. These are: transferable prefix,
            plus latest establishment event sequence number plus latest
            establishment event digest, plus indexed event signature.
            When latest establishment event is multisig then there will
            be multiple quadruples one per signing key, each a dup at same db key.
            dgKey
            DB is keyed by identifier prefix plus digest of serialized event
            More than one value per DB key is allowed

        .pses is named sub DB of partially signed key event escrows
            that each map pre + sequence number to serialized event digest.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pwes is named sub DB of partially witnessed key event escrowes
            that each map pre + sequence number to serialized event digest.
            these are for escrows of events with verified signatures but not
            yet verified witness reciepts.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pdes is named sub DB of partially delegated key event escrows
            that each map pre + sequence number to serialized event digest. This is
            used in conjunction with .udes which escrows the associated seal
            source couple.
            snKey
            Values are digests used to lookup delegated event in .evts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            More than one value per DB key is allowed

        .udes is named sub DB of unverified delegation seal source couple escrows
            that map (pre, digest) of delegated event to delegating seal source
            couple (sn, dig) that provides source delegator event seal.
            Each couple is concatenation of fully qualified items, snu+dig
            of delegating source event in which seal of delegated event appears.
            dgKey
            Values are serialized instances of CatCesrSuber as couples
            (Seqner.qb64b, Saider.qb64b) used to lookup source event in delegator's
            KEL.
            DB is keyed by identifier prefix plus digest of key event
            Only one value per DB key is allowed
            Once escrow is accepted then delegation approval source seal couples
            go into .aess database of authorizing event source seal couples

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
            DB is keyed by identifier prefix plus sequence number of key event
            More than one value per DB key is allowed

        .dels is named sub DB of duplicitous event log tables that map sequence numbers
            to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            More than one value per DB key is allowed

        .ldes is named sub DB of likely duplicitous escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifier prefix plus sequence number of key event
            More than one value per DB key is allowed


        .states (subkey stts.) is named subDB instance of SerderSuber that maps a prefix
            to the latest keystate for that prefix. Used by ._kevers.db for read
            through cache of key state to reload kevers in memory

        .habs is named subDB instance of Komer that maps habitat names to habitat
            application state. Includes habitat identifier prefix
            key is habitat name str
            value is serialized HabitatRecord dataclass

        .nmsp is named subDB instance of Komer that maps habitat namespaces and names to habitat
            application state. Includes habitat identifier prefix
            key is habitat namespace + b'\x00' + name str
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

        .mpids is named subDB instance of CesrIoSetSuber mapping payload SAID (of 'e' block)
            to the SAID of the `exn` messages is was contained in.  This aggregates
            identical message bodies across participants in group multisig body trying
            to reach concensus on events or credentials.

        .pubs is CatCesrIoSetSuber with subkey="pubs." of concatenated tuples
        (qb64 pre, qb64 snh) indexed by qb64 of public key. Maps each signing
        public key from establishment event to the events's prefix and sequence number
        so can look up an event by any of its signing keys. Updated by Kever.logEvent

        .digs is CatCesrIoSetSuber with subkey="digs." of of concatenated tuples
        (qb64 pre, qb64 snh) indexed by qb64 of digest of next signing public key.
        Maps each next signing public key digest from establishment event to
        the events's prefix and sequence number so can look up an event by any
        of its next public signing key digests. Updated by Kever.logEvent

        Missing ToDo XXXX other attributes as sub dbs not documented here
            such as .wits etc

    Properties:
        kevers (dbdict): read through cache of kevers of states for KELs in db

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
        self.prefixes = oset()  # should change to hids for hab ids
        self.groups = oset()  # group hab ids
        self._kevers = dbdict()
        self._kevers.db = self  # assign db for read through cache of kevers

        if (mapSize := os.getenv(KERIBaserMapSizeKey)) is not None:
            try:
                self.MapSize = int(mapSize)
            except ValueError:
                logger.error("KERI_BASER_MAP_SIZE must be an integer value >1!")
                raise

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
        self.kels = self.env.open_db(key=b'kels.', dupsort=True)
        self.dtss = self.env.open_db(key=b'dtss.')
        self.aess = self.env.open_db(key=b'aess.')
        self.sigs = self.env.open_db(key=b'sigs.', dupsort=True)
        self.wigs = self.env.open_db(key=b'wigs.', dupsort=True)
        self.rcts = self.env.open_db(key=b'rcts.', dupsort=True)
        self.ures = self.env.open_db(key=b'ures.', dupsort=True)
        self.vrcs = self.env.open_db(key=b'vrcs.', dupsort=True)
        self.vres = self.env.open_db(key=b'vres.', dupsort=True)
        self.pses = self.env.open_db(key=b'pses.', dupsort=True)
        self.pwes = self.env.open_db(key=b'pwes.', dupsort=True)
        self.pdes = subing.OnIoDupSuber(db=self, subkey='pdes.')
        self.udes = subing.CatCesrSuber(db=self, subkey='udes.',
                                        klas=(coring.Seqner, coring.Saider))
        self.uwes = self.env.open_db(key=b'uwes.', dupsort=True)
        self.ooes = self.env.open_db(key=b'ooes.', dupsort=True)
        self.dels = self.env.open_db(key=b'dels.', dupsort=True)
        self.ldes = self.env.open_db(key=b'ldes.', dupsort=True)
        self.qnfs = subing.IoSetSuber(db=self, subkey="qnfs.", dupsort=True)

        # events as ordered by first seen ordinals
        self.fons = subing.CesrSuber(db=self, subkey='fons.', klas=core.Number)

        self.migs = subing.CesrSuber(db=self, subkey="migs.", klas=coring.Dater)
        self.vers = subing.Suber(db=self, subkey="vers.")

        # event source local (protected) or non-local (remote not protected)
        self.esrs = koming.Komer(db=self,
                                   schema=EventSourceRecord,
                                   subkey='esrs.')

        # misfit escrows whose processing may change the .esrs event source record
        self.misfits = subing.IoSetSuber(db=self, subkey='mfes.')

        # delegable events escrows. events with local delegator that need approval
        self.delegables = subing.IoSetSuber(db=self, subkey='dees.')

        # Kever state made of KeyStateRecord key states
        # TODO: clean
        self.states = koming.Komer(db=self,
                                   schema=KeyStateRecord,
                                   subkey='stts.')

        self.wits = subing.CesrIoSetSuber(db=self, subkey="wits.", klas=coring.Prefixer)

        # habitat application state keyed by habitat name, includes prefix
        self.habs = koming.Komer(db=self,
                                 subkey='habs.',
                                 schema=HabitatRecord, )
        # habitat name database mapping (domain,name) as key to Prefixer
        self.names = subing.Suber(db=self, subkey='names.', sep="^")

        # SAD support datetime stamps and signatures indexed and not-indexed
        # all sad  sdts (sad datetime serializations) maps said to date-time
        self.sdts = subing.CesrSuber(db=self, subkey='sdts.', klas=coring.Dater)

        # all sad ssgs (sad indexed signature serializations) maps SAD quadkeys
        # given by quadruple (saider.qb64, prefixer.qb64, seqner.q64, diger.qb64)
        #  of reply and trans signer's key state est evt to val Siger for each
        # signature.
        self.ssgs = subing.CesrIoSetSuber(db=self, subkey='ssgs.', klas=indexing.Siger)

        # all sad scgs  (sad non-indexed signature serializations) maps SAD SAID
        # to couple (Verfer, Cigar) of nontrans signer of signature in Cigar
        # nontrans qb64 of Prefixer is same as Verfer
        self.scgs = subing.CatCesrIoSetSuber(db=self, subkey='scgs.',
                                             klas=(coring.Verfer, coring.Cigar))

        # all reply messages. Maps reply said to serialization. Replys are
        # versioned sads ( with version string) so use Serder to deserialize and
        # use  .sdts, .ssgs, and .scgs for datetimes and signatures
        # TODO: clean
        self.rpys = subing.SerderSuber(db=self, subkey='rpys.')

        # all reply escrows indices of partially signed reply messages. Maps
        # route in reply to single (Saider,)  of escrowed reply.
        # Routes such as /end/role  /loc/schema
        self.rpes = subing.CesrIoSetSuber(db=self, subkey='rpes.',
                                          klas=coring.Saider)

        # auth AuthN/AuthZ by controller at cid of endpoint provider at eid
        # maps key=cid.role.eid to val=said of end reply
        # TODO: clean
        self.eans = subing.CesrSuber(db=self, subkey='eans.', klas=coring.Saider)

        # auth AuthN/AuthZ by endpoint provider at eid of location at scheme url
        # maps key=cid.role.eid to val=said of end reply
        self.lans = subing.CesrSuber(db=self, subkey='lans.', klas=coring.Saider)

        # service endpoint identifier (eid) auths keyed by controller cid.role.eid
        # data extracted from reply /end/role/add or /end/role/cut
        self.ends = koming.Komer(db=self, subkey='ends.',
                                 schema=EndpointRecord, )

        # service endpoint locations keyed by eid.scheme  (endpoint identifier)
        # data extracted from reply loc
        self.locs = koming.Komer(db=self,
                                 subkey='locs.',
                                 schema=LocationRecord, )
        # observed oids by watcher by cid.aid.oid  (endpoint identifier)
        # data extracted from reply loc
        self.obvs = koming.Komer(db=self,
                                 subkey='obvs.',
                                 schema=ObservedRecord, )

        # index of last retrieved message from witness mailbox
        # TODO: clean
        self.tops = koming.Komer(db=self,
                                 subkey='witm.',
                                 schema=TopicsRecord, )

        # group partial signature escrow
        self.gpse = subing.CatCesrIoSetSuber(db=self, subkey='gpse.',
                                             klas=(core.Number, coring.Saider))

        # group delegate escrow
        self.gdee = subing.CatCesrIoSetSuber(db=self, subkey='gdee.',
                                             klas=(core.Number, coring.Saider))

        # group partial witness escrow
        self.gpwe = subing.CatCesrIoSetSuber(db=self, subkey='gdwe.',
                                             klas=(core.Number, coring.Saider))

        # completed group multisig
        # TODO: clean
        self.cgms = subing.CesrSuber(db=self, subkey='cgms.',
                                     klas=coring.Saider)

        # exchange message partial signature escrow
        self.epse = subing.SerderSuber(db=self, subkey="epse.")

        # exchange message PS escrow date time of message
        self.epsd = subing.CesrSuber(db=self, subkey="epsd.",
                                     klas=coring.Dater)

        # exchange messages
        # TODO: clean
        self.exns = subing.SerderSuber(db=self, subkey="exns.")

        # Forward pointer to a provided reply message
        # TODO: clean
        self.erpy = subing.CesrSuber(db=self, subkey="erpy.", klas=coring.Saider)

        # exchange message signatures
        # TODO: clean
        self.esigs = subing.CesrIoSetSuber(db=self, subkey='esigs.', klas=indexing.Siger)

        # exchange message signatures
        # TODO: clean
        self.ecigs = subing.CatCesrIoSetSuber(db=self, subkey='ecigs.',
                                              klas=(coring.Verfer, coring.Cigar))

        # exchange pathed attachments
        # TODO: clean
        self.epath = subing.IoSetSuber(db=self, subkey=".epath")

        self.essrs = subing.CesrIoSetSuber(db=self, subkey=".essrs", klass=coring.Texter)

        # accepted signed 12-word challenge response exn messages keys by prefix of signer
        # TODO: clean
        self.chas = subing.CesrIoSetSuber(db=self, subkey='chas.', klas=coring.Saider)

        # successfull signed 12-word challenge response exn messages keys by prefix of signer
        # TODO: clean
        self.reps = subing.CesrIoSetSuber(db=self, subkey='reps.', klas=coring.Saider)

        # authorzied well known OOBIs
        # TODO: clean
        self.wkas = koming.IoSetKomer(db=self, subkey='wkas.', schema=WellKnownAuthN)

        # KSN support datetime stamps and signatures indexed and not-indexed
        # all ksn  kdts (key state datetime serializations) maps said to date-time
        # TODO: clean
        self.kdts = subing.CesrSuber(db=self, subkey='kdts.', klas=coring.Dater)

        # all key state messages. Maps key state said to serialization. ksns are
        # KeyStateRecords so use ._asdict or ._asjson as appropriate
        # use  .kdts, .ksgs, and .kcgs for datetimes and signatures
        # TODO: clean
        self.ksns = koming.Komer(db=self,
                                schema=KeyStateRecord,
                                subkey='ksns.')

        # key state SAID database for successfully saved key state notices
        # maps key=(prefix, aid) to val=said of key state
        # TODO: clean
        self.knas = subing.CesrSuber(db=self, subkey='knas.', klas=coring.Saider)

        # Watcher watched SAID database for successfully saved watched AIDs for a watcher
        # maps key=(cid, aid, oid) to val=said of rpy message
        # TODO: clean
        self.wwas = subing.CesrSuber(db=self, subkey='wwas.', klas=coring.Saider)

        # config loaded oobis to be processed asynchronously, keyed by oobi URL
        # TODO: clean
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
        # TODO: clean
        self.roobi = koming.Komer(db=self,
                                  subkey='roobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Well known OOBIs that are to be used for mfa against a resolved OOBI.
        # TODO: clean
        self.woobi = koming.Komer(db=self,
                                  subkey='woobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Well known OOBIs that are to be used for mfa against a resolved OOBI.
        # TODO: clean
        self.moobi = koming.Komer(db=self,
                                  subkey='moobi.',
                                  schema=OobiRecord,
                                  sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Multifactor well known OOBI auth records to process.  Keys by controller URL
        # TODO: clean
        self.mfa = koming.Komer(db=self,
                                subkey='mfa.',
                                schema=OobiRecord,
                                sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # Resolved multifactor well known OOBI auth records.  Keys by controller URL
        # TODO: clean
        self.rmfa = koming.Komer(db=self,
                                 subkey='rmfa.',
                                 schema=OobiRecord,
                                 sep=">")  # Use seperator not a allowed in URLs so no splitting occurs.

        # JSON schema SADs keys by the SAID
        # TODO: clean
        self.schema = subing.SchemerSuber(db=self,
                                          subkey='schema.')

        # Field values for contact information for remote identifiers.  Keyed by prefix/field
        # TODO: clean
        self.cfld = subing.Suber(db=self,
                                 subkey="cfld.")

        # Global settings for the Habery environment
        self.hbys = subing.Suber(db=self, subkey='hbys.')

        # Signed contact data, keys by prefix
        # TODO: clean
        self.cons = subing.Suber(db=self,
                                 subkey="cons.")

        # Transferable signatures on contact data
        # TODO: clean
        self.ccigs = subing.CesrSuber(db=self, subkey='ccigs.', klas=coring.Cigar)

        # Chunked image data for contact information for remote identifiers
        # TODO: clean
        self.imgs = self.env.open_db(key=b'imgs.')

        # Delegation escrow dbs #
        # delegated partial witness escrow
        self.dpwe = subing.SerderSuber(db=self, subkey='dpwe.')

        # delegated unanchored escrow
        self.dune = subing.SerderSuber(db=self, subkey='dune.')

        # delegate publication escrow for sending delegator info to my witnesses
        self.dpub = subing.SerderSuber(db=self, subkey='dpub.')

        # completed group delegated AIDs
        # TODO: clean
        self.cdel = subing.CesrSuber(db=self, subkey='cdel.',
                                     klas=coring.Saider)

        # multisig sig embed payload SAID mapped to containing exn messages across group multisig participants
        # TODO: clean
        self.meids = subing.CesrIoSetSuber(db=self, subkey="meids.", klas=coring.Saider)

        # multisig sig embed payload SAID mapped to group multisig participants AIDs
        # TODO: clean
        self.maids = subing.CesrIoSetSuber(db=self, subkey="maids.", klas=coring.Prefixer)

        self.reload()

        return self.env

    def reload(self):
        """
        Reload stored prefixes and Kevers from .habs

        """
        # Check migrations to see if this database is up to date.  Error otherwise
        if not self.current:
            raise kering.DatabaseError("Database migrations must be run.")

        removes = []
        for keys, data in self.habs.getItemIter():
            if (ksr := self.states.get(keys=data.hid)) is not None:
                try:
                    kever = eventing.Kever(state=ksr,
                                           db=self,
                                           local=True)
                except kering.MissingEntryError as ex:  # no kel event for keystate
                    removes.append(keys)  # remove from .habs
                    continue
                self.kevers[kever.prefixer.qb64] = kever
                self.prefixes.add(kever.prefixer.qb64)
                if data.mid:  # group hab
                    self.groups.add(data.hid)

            elif data.mid is None:  # in .habs but no corresponding key state and not a group so remove
                removes.append(keys)  # no key state or KEL event for .hab record

        for keys in removes:  # remove bare .habs records
            self.habs.rem(keys=keys)

    def migrate(self):
        """ Run all migrations required

        Run all migrations  that are required from the current version of database up to the current version
         of the software that have not already been run.

         Sets the version of the database to the current version of the software after successful completion
         of required migrations

        """
        for (version, migrations) in MIGRATIONS:
            # Check to see if this is for an older version
            if self.version is not None and semver.compare(version, self.version) != 1:
                continue

            for migration in migrations:
                modName = f"keri.db.migrations.{migration}"
                if self.migs.get(keys=(migration,)) is not None:
                    continue

                mod = importlib.import_module(modName)
                try:
                    print(f"running migration {modName}")
                    mod.migrate(self)
                except Exception as e:
                    print(f"\nAbandoning migration {migration} with error: {e}")
                    return

                self.migs.pin(keys=(migration,), val=coring.Dater())

        self.version = keri.__version__

    @property
    def current(self):
        """ Current property determines if we are at the current database migration state.

         If the database version matches the library version return True
         If the current database version is behind the current library version, check for migrations
            - If there are migrations to run, return False
            - If there are no migrations to run, reset database version to library version and return True
         If the current database version is ahead of the current library version, raise exception

         """
        if self.version == keri.__version__:
            return True

        # If database version is ahead of library version, throw exception
        if self.version is not None and semver.compare(self.version, keri.__version__) == 1:
            raise kering.ConfigurationError(
                f"Database version={self.version} is ahead of library version={keri.__version__}")

        last = MIGRATIONS[-1]
        # If we aren't at latest version, but there are no outstanding migrations, reset version to latest
        if self.migs.get(keys=(last[1][0],)) is not None:
            return True

        # We have migrations to run
        return False

    def complete(self, name=None):
        """ Returns list of tuples of migrations completed with date of completion

        Parameters:
            name(str): optional name of migration to check completeness

        Returns:
            list: tuples of migration,date of completed migration names and the date of completion

        """
        migrations = []
        if not name:
            for version, migs in MIGRATIONS:
                for mig in migs:
                    dater = self.migs.get(keys=(mig,))
                    migrations.append((mig, dater))
        else:
            if name not in MIGRATIONS or not self.migs.get(keys=(name,)):
                raise ValueError(f"No migration named {name}")
            migrations.append((name, self.migs.get(keys=(name,))))

        return migrations

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
                    clean=True) as copy:  # copy is Baser instance

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

                # This is the list of non-set based databases that are not created as part of event processing.
                # for now we are just copying them from self to copy without worrying about being able to
                # reprocess them.  We need a more secure method in the future
                unsecured = ["hbys", "schema", "states", "rpys", "eans", "tops", "cgms", "exns", "erpy",
                             "kdts", "ksns", "knas", "oobis", "roobi", "woobi", "moobi", "mfa", "rmfa",
                             "cfld", "cons", "ccigs", "cdel", "migs"]

                for name in unsecured:
                    srcdb = getattr(self, name)
                    cpydb = getattr(copy, name)
                    for keys, val in srcdb.getItemIter():
                        cpydb.put(keys=keys, val=val)

                # This is the list of set based databases that are not created as part of event processing.
                # for now we are just copying them from self to copy without worrying about being able to
                # reprocess them.  We need a more secure method in the future
                sets = ["esigs", "ecigs", "epath", "chas", "reps", "wkas", "meids", "maids"]
                for name in sets:
                    srcdb = getattr(self, name)
                    cpydb = getattr(copy, name)
                    for keys, val in srcdb.getItemIter():
                        cpydb.add(keys=keys, val=val)

                # Insecure raw imgs database copy.
                for (key, val) in self.getTopItemIter(self.imgs):
                    copy.imgs.setVal(key=key, val=val)

                # clone .habs  habitat name prefix Komer subdb
                # copy.habs = koming.Komer(db=copy, schema=HabitatRecord, subkey='habs.')  # copy
                for keys, val in self.habs.getItemIter():
                    if val.hid in copy.kevers:  # only copy habs that verified
                        copy.habs.put(keys=keys, val=val)
                        ns = "" if val.domain is None else val.domain
                        copy.names.put(keys=(ns, val.name), val=val.hid)
                        copy.prefixes.add(val.hid)
                        if val.mid:  # a group hab
                            copy.groups.add(val.hid)

                # clone .ends and .locs databases
                for (cid, role, eid), val in self.ends.getItemIter():
                    exists = False  # only copy if entries in both .ends and .locs
                    for scheme in ("https", "http", "tcp"):  # all supported schemes
                        lval = self.locs.get(keys=(eid, scheme))
                        if lval:
                            exists = True  # loc with matching cid and rol
                            copy.locs.put(keys=(eid, scheme), val=lval)
                    if exists:  # only copy end if has at least one matching loc
                        copy.ends.put(keys=(cid, role, eid), val=val)

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

            # clear and clone .gids
            self.groups.clear()
            self.groups.update(copy.groups)

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

        Parameters:
            pre is bytes of itdentifier prefix
            fn is int fn to resume replay. Earliset is fn=0

        Returns:
           msgs (Iterator): over all items with pre starting at fn
        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for _, fn, dig in self.getFelItemPreIter(pre, fn=fn):
            try:
                msg = self.cloneEvtMsg(pre=pre, fn=fn, dig=dig)
            except Exception:
                continue  # skip this event
            yield msg


    def cloneAllPreIter(self):
        """
        Returns iterator of first seen event messages with attachments for all
        identifier prefixes starting at key. If key == b'' then start at first
        key in databse. Use key to resume replay.
        Essentially a replay in first seen order with attachments of entire
        set of FELs.

        Returns:
           msgs (Iterator): over all items in db

        """
        for pre, fn, dig in self.getFelItemAllPreIter():
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
        atc.extend(core.Counter(code=core.Codens.ControllerIdxSigs,
                                count=len(sigs), gvrsn=kering.Vrsn_1_0).qb64b)
        for sig in sigs:
            atc.extend(sig)

        # add indexed witness signatures to attachments
        if wigs := self.getWigs(key=dgkey):
            atc.extend(core.Counter(code=core.Codens.WitnessIdxSigs,
                                    count=len(wigs), gvrsn=kering.Vrsn_1_0).qb64b)
            for wig in wigs:
                atc.extend(wig)

        # add authorizer (delegator/issuer) source seal event couple to attachments
        couple = self.getAes(dgkey)
        if couple is not None:
            atc.extend(core.Counter(code=core.Codens.SealSourceCouples,
                                    count=1, gvrsn=kering.Vrsn_1_0).qb64b)
            atc.extend(couple)

        # add trans endorsement quadruples to attachments not controller
        # may have been originally key event attachments or receipted endorsements
        if quads := self.getVrcs(key=dgkey):
            atc.extend(core.Counter(code=core.Codens.TransReceiptQuadruples,
                                    count=len(quads), gvrsn=kering.Vrsn_1_0).qb64b)
            for quad in quads:
                atc.extend(quad)

        # add nontrans endorsement couples to attachments not witnesses
        # may have been originally key event attachments or receipted endorsements
        if coups := self.getRcts(key=dgkey):
            atc.extend(core.Counter(code=core.Codens.NonTransReceiptCouples,
                                    count=len(coups), gvrsn=kering.Vrsn_1_0).qb64b)
            for coup in coups:
                atc.extend(coup)

        # add first seen replay couple to attachments
        if not (dts := self.getDts(key=dgkey)):
            raise kering.MissingEntryError("Missing datetime for dig={}.".format(dig))
        atc.extend(core.Counter(code=core.Codens.FirstSeenReplayCouples,
                                count=1, gvrsn=kering.Vrsn_1_0).qb64b)
        atc.extend(core.Number(num=fn, code=core.NumDex.Huge).qb64b)  # may not need to be Huge
        atc.extend(coring.Dater(dts=bytes(dts)).qb64b)

        # prepend pipelining counter to attachments
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        pcnt = core.Counter(code=core.Codens.AttachmentGroup,
                            count=(len(atc) // 4), gvrsn=kering.Vrsn_1_0).qb64b
        msg.extend(pcnt)
        msg.extend(atc)
        return msg

    def cloneDelegation(self, kever):
        """
        Recursively clone delegation chain from AID of Kever if one exits.

        Parameters:
            kever (Kever): Kever from which to clone the delegator's AID.

        """
        if kever.delegated and kever.delpre in self.kevers:
            dkever = self.kevers[kever.delpre]
            yield from self.cloneDelegation(dkever)

            for dmsg in self.clonePreIter(pre=kever.delpre, fn=0):
                yield dmsg

    def fetchAllSealingEventByEventSeal(self, pre, seal, sn=0):
        """
        Search through a KEL for the event that contains a specific anchored
        SealEvent type of provided seal but in dict form and is also fully
        witnessed. Searchs from sn forward (default = 0).Searches all events in
        KEL of pre including disputed and/or superseded events.
        Returns the Serder of the first event with the anchored SealEvent seal,
            None if not found


        Parameters:
            pre (bytes|str): identifier of the KEL to search
            seal (dict): dict form of Seal of any type SealEvent to find in anchored
                seals list of each event
            sn (int): beginning sn to search

        """
        if tuple(seal) != eventing.SealEvent._fields:  # wrong type of seal
            return None

        seal = eventing.SealEvent(**seal)  #convert to namedtuple

        for evt in self.getEvtPreIter(pre=pre, sn=sn):  # includes disputed & superseded
            srdr = serdering.SerderKERI(raw=evt.tobytes())
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == eventing.SealEvent._fields:
                    eseal = eventing.SealEvent(**eseal)  # convert to namedtuple
                    if seal == eseal and self.fullyWitnessed(srdr):
                        return srdr
        return None

    # use alias here until can change everywhere for  backwards compatibility
    findAnchoringSealEvent = fetchAllSealingEventByEventSeal  # alias


    def fetchLastSealingEventByEventSeal(self, pre, seal, sn=0):
        """
        Search through a KEL for the last event at any sn but that contains a
        specific anchored event seal of namedtuple SealEvent type that matches
        the provided seal in dict form and is also fully witnessed.
        Searchs from provided sn forward (default = 0).
        Searches only last events in KEL of pre so does not include disputed
        and/or superseded events.

        Returns:
            srdr (Serder): instance of the first event with the matching
                           anchoring SealEvent seal,
                        None if not found

        Parameters:
            pre (bytes|str): identifier of the KEL to search
            seal (dict): dict form of Seal of any type SealEvent to find in anchored
                seals list of each event
            sn (int): beginning sn to search

        """
        if tuple(seal) != eventing.SealEvent._fields:  # wrong type of seal
            return None

        seal = eventing.SealEvent(**seal)  #convert to namedtuple

        for evt in self.getEvtLastPreIter(pre=pre, sn=sn):  # no disputed or superseded
            srdr = serdering.SerderKERI(raw=evt.tobytes())
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == eventing.SealEvent._fields:
                    eseal = eventing.SealEvent(**eseal)  # convert to namedtuple
                    if seal == eseal and self.fullyWitnessed(srdr):
                        return srdr
        return None



    def fetchLastSealingEventBySeal(self, pre, seal, sn=0):
        """Only searches last event at any sn therefore does not search
        any disputed or superseded events.
        Search through last event at each sn in KEL for the event that contains
        an anchored Seal with same Seal type as provided seal but in dict form.
        Searchs from sn forward (default = 0).
        Returns the Serder of the first found event with the anchored Seal seal,
            None if not found

        Parameters:
            pre (bytes|str): identifier of the KEL to search
            seal (dict): dict form of Seal of any type to find in anchored
                seals list of each event
            sn (int): beginning sn to search

        """
        # create generic Seal namedtuple class using keys from provided seal dict
        Seal = namedtuple('Seal', list(seal))  # matching type

        for evt in self.getEvtLastPreIter(pre=pre, sn=sn):  # only last evt at sn
            srdr = serdering.SerderKERI(raw=evt.tobytes())
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == Seal._fields:  # same type of seal
                    eseal = Seal(**eseal)  #convert to namedtuple
                    if seal == eseal and self.fullyWitnessed(srdr):
                        return srdr
        return None

    def signingMembers(self, pre: str):
        """ Find signing members of a multisig group aid.

        Using the pubs index to find members of a signing group

        Parameters:
            pre (str): qb64 identifier prefix to find members

        Returns:
            list: qb64 identifier prefixes of signing members for provided aid

        """
        if (habord := self.habs.get(keys=(pre,))) is None:
            return None

        return habord.smids

    def rotationMembers(self, pre: str):
        """ Find rotation members of a multisig group aid.

        Using the digs index to lookup member pres of a group aid

        Parameters:
            pre (str): qb64 identifier prefix to find members

        Returns:
            list: qb64 identifier prefixes of rotation members for provided aid
        """
        if (habord := self.habs.get(keys=(pre,))) is None:
            return None

        return habord.rmids

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
            sserder = serdering.SerderKERI(raw=bytes(sraw))
            if dig is not None and not sserder.compare(said=dig):  # endorser's dig not match event
                raise kering.ValidationError("Bad proof sig group at sn = {}"
                                             " for ksn = {}."
                                             "".format(sn, sserder.sad))

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


    def getEvtPreIter(self, pre, sn=0):
        """
        Returns iterator of event messages without attachments
        in sn order from the KEL of identifier prefix pre.
        Essentially a replay of all event messages without attachments
        for each sn from the KEL of pre including superseded duplicates

        Parameters:
            pre (bytes|str): identifier prefix
            sn (int): sequence number (default 0) to begin interation
        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for dig in self.getKelIter(pre, sn=sn):
            try:
                dgkey = dbing.dgKey(pre, dig)  # get message
                if not (raw := self.getEvt(key=dgkey)):
                    raise kering.MissingEntryError("Missing event for dig={}.".format(dig))

            except Exception:
                continue  # skip this event

            yield raw  # event message


    def getEvtLastPreIter(self, pre, sn=0):
        """
        Returns iterator of event messages without attachments
        in sn order from the KEL of identifier prefix pre.
        Essentially a replay of all event messages without attachments
        for each sn from the KEL of pre including superseded duplicates

        Parameters:
            pre (bytes|str): identifier prefix
            sn (int): sequence number (default 0) to begin interation
        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for dig in self.getKelLastIter(pre, sn=sn):
            try:

                dgkey = dbing.dgKey(pre, dig)  # get message
                if not (raw := self.getEvt(key=dgkey)):
                    raise kering.MissingEntryError("Missing event for dig={}.".format(dig))

            except Exception:
                continue  # skip this event

            yield raw  # event message


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
        return self.appendOnVal(db=self.fels, key=pre, val=val)

    def getFelItemPreIter(self, pre, fn=0):
        """
        Returns iterator of all (pre, fn, dig) triples in first seen order for
        all events with same prefix, pre, in database. Items are sorted by
        fnKey(pre, fn) where fn is first seen order number int.
        Returns a First Seen Event Log FEL.
        Returned items are duples of (fn, dig): Where fn is first seen order
        number int and dig is event digest for lookup in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            pre is bytes of itdentifier prefix
            fn is int fn to resume replay. Earliset is fn=0

        Returns:
           items (Iterator[(pre, fn, val)]): over all items starting at pre, on
        """
        return self.getOnItemIter(db=self.fels, key=pre, on=fn)


    def getFelItemAllPreIter(self):
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
        #return self.getAllOnItemAllPreIter(db=self.fels, key=key)
        return self.getOnItemIter(db=self.fels, key=b'')

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
        return self.putIoDupVals(self.ures, key, vals)

    def addUre(self, key, val):
        """
        Use snKey()
        Add receipt triple val bytes as dup to key in db
        Triple is dig+pre+cig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.ures, key, val)

    def getUres(self, key):
        """
        Use snKey()
        Return list of receipt triplets at key
        Triple is dig+pre+cig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.ures, key)

    def getUresIter(self, key):
        """
        Use snKey()
        Return iterator of receipt triplets at key
        Triple is dig+pre+cig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValsIter(self.ures, key)

    def getUreLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event triple val at key
        Triple is dig+pre+cig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.ures, key)


    def getUreItemIter(self, key=b''):
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
        return self.getTopIoDupItemIter(self.ures, key)
        #return self.getIoDupItemsNextIter(self.ures, key, skip)

    def cntUres(self, key):
        """
        Use snKey()
        Return count of receipt triplets at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.ures, key)

    def delUres(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoDupVals(self.ures, key)

    def delUre(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoDupVal(self.ures, key, val)

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
        return self.putIoDupVals(self.vres, key, vals)

    def addVre(self, key, val):
        """
        Use snKey()
        Add receipt quintuple val bytes as dup to key in db
        Quinlet is edig + spre + ssnu + sdig +sig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.vres, key, val)

    def getVres(self, key):
        """
        Use snKey()
        Return list of receipt quinlets at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.vres, key)

    def getVresIter(self, key):
        """
        Use snKey()
        Return iterator of receipt quinlets at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValsIter(self.vres, key)

    def getVreLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event quintuple val at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.vres, key)

    def getVreItemIter(self, key=b''):
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
        return self.getTopIoDupItemIter(self.vres, key)
        #return self.getIoDupItemsNextIter(self.vres, key, skip)

    def cntVres(self, key):
        """
        Use snKey()
        Return count of receipt quinlets at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.vres, key)

    def delVres(self, key):
        """
         Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoDupVals(self.vres, key)

    def delVre(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoDupVal(self.vres, key, val)

    def putKes(self, key, vals):
        """
        Use snKey()
        Write each key event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoDupVals(self.kels, key, vals)

    def addKe(self, key, val):
        """
        Use snKey()
        Add key event val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.kels, key, val)

    def getKes(self, key):
        """
        Use snKey()
        Return list of key event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.kels, key)

    def getKeLast(self, key):
        """
        Use snKey()
        Return last inserted dup key event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.kels, key)

    def cntKes(self, key):
        """
        Use snKey()
        Return count of dup key event dig val at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.kels, key)

    def delKes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoDupVals(self.kels, key)


    def getKelIter(self, pre, sn=0):
        """
        Returns iterator of all dup vals in insertion order for all entries
        with same prefix across all sequence numbers without gaps. Stops if
        encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        db .kels values are digests used to lookup event in .evts sub DB

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
        db is opened as named sub db with dupsort=True

        Parameters:
            pre (bytes | str): of itdentifier prefix prepended to sn in key
                within sub db's keyspace
            sn (int): initial sequence number to begin at
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes

        return (self.getOnIoDupValIter(self.kels, pre, on=sn))

        #return self.getOnIoDupValsAllPreIter(self.kels, pre, on=sn)


    def getKelBackIter(self, pre, sn=0):
        """
        Returns iterator of all dup vals in insertion order for all entries
        with same prefix across all sequence numbers without gaps in decreasing
        order starting with first sequence number sn. Stops if encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        db .kels values are digests used to lookup event in .evts sub DB

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
        db is opened as named sub db with dupsort=True

        Parameters:
            pre (bytes | str): of itdentifier prefix prepended to sn in key
                within sub db's keyspace
            sn (int):
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getOnIoDupValBackIter(self.kels, pre, sn)


    def getKelLastIter(self, pre, sn=0):
        """
        Returns iterator of last one of dup vals at each key in insertion order
        for all entries with same prefix across all sequence numbers without gaps.
        Stops if encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        db .kels values are digests used to lookup event in .evts sub DB

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
        db is opened as named sub db with dupsort=True

        Parameters:
            pre (bytes | str): of itdentifier prefix prepended to sn in key
                within sub db's keyspace
            sn (int); sequence number to being iteration
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getOnIoDupLastValIter(self.kels, pre, on=sn)


    def putPses(self, key, vals):
        """
        Use snKey()
        Write each partial signed escrow event entry from list of bytes dig vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoDupVals(self.pses, key, vals)

    def addPse(self, key, val):
        """
        Use snKey()
        Add Partial signed escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.pses, key, val)

    def getPses(self, key):
        """
        Use snKey()
        Return list of partial signed escrowed event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.pses, key)

    def getPsesIter(self, key):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event dig vals at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValsIter(self.pses, key)

    def getPseLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event dig val at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.pses, key)

    def getPseItemIter(self, key=b''):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getTopIoDupItemIter(self.pses, key)
        #return self.getIoDupItemsNextIter(self.pses, key, skip)

    def cntPses(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.pses, key)

    def delPses(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key  exists in db Else False
        """
        return self.delIoDupVals(self.pses, key)

    def delPse(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoDupVal(self.pses, key, val)


    def putPwes(self, key, vals):
        """
        Use snKey()
        Write each partial witnessed escrow event entry from list of bytes dig vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoDupVals(self.pwes, key, vals)

    def addPwe(self, key, val):
        """
        Use snKey()
        Add Partial witnessed escrow dig val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.pwes, key, val)

    def getPwes(self, key):
        """
        Use snKey()
        Return list of witnessed signed escrowed event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.pwes, key)

    def getPwesIter(self, key):
        """
        Use sgKey()
        Return iterator of partial witnessed escrowed event dig vals at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValsIter(self.pwes, key)

    def getPweLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial witnessed escrowed event dig val at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.pwes, key)

    def getPweItemIter(self, key=b''):
        """
        Use sgKey()
        Return iterator of partial witnessed escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getTopIoDupItemIter(self.pwes, key)
        #return self.getIoDupItemsNextIter(self.pwes, key, skip)

    #def getPweIoDupItemIter(self, key=b''):
        #"""
        #Use sgKey()
        #Return iterator of partial witnessed escrowed event dig items at next key after key.
        #Items is (key, val) where proem has already been stripped from val
        #If key is b'' empty then returns dup items at first key.
        #If skip is False and key is not b'' empty then returns dup items at key
        #Raises StopIteration Error when empty
        #Duplicates are retrieved in insertion order.
        #"""
        #return self.getTopIoDupItemIter(self.pwes, key)

    def cntPwes(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.pwes, key)

    def delPwes(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key  exists in db Else False
        """
        return self.delIoDupVals(self.pwes, key)

    def delPwe(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoDupVal(self.pwes, key, val)

    def putUwes(self, key, vals):
        """
        Use snKey()
        Write each entry from list of bytes witness receipt couples vals to key
        Witness couple is edig+wig
        Adds to existing receipts at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoDupVals(self.uwes, key, vals)

    def addUwe(self, key, val):
        """
        Use snKey()
        Add receipt couple val bytes as dup to key in db
        Witness couple is edig+wig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.uwes, key, val)

    def getUwes(self, key):
        """
        Use snKey()
        Return list of receipt couples at key
        Witness couple is edig+wig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.uwes, key)

    def getUwesIter(self, key):
        """
        Use snKey()
        Return iterator of receipt couples at key
        Witness couple is edig+wig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValsIter(self.uwes, key)

    def getUweLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed receipt couple val at key
        Witness couple is edig+wig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.uwes, key)

    def getUweItemIter(self, key=b''):
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
        return self.getTopIoDupItemIter(self.uwes, key)
        #return self.getIoDupItemsNextIter(self.uwes, key, skip)

    def cntUwes(self, key):
        """
        Use snKey()
        Return count of receipt couples at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.uwes, key)

    def delUwes(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoDupVals(self.uwes, key)

    def delUwe(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoDupVal(self.uwes, key, val)

    def putOoes(self, key, vals):
        """
        Use snKey()
        Write each out of order escrow event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoDupVals(self.ooes, key, vals)

    def addOoe(self, key, val):
        """
        Use snKey()
        Add out of order escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.ooes, key, val)

    def getOoes(self, key):
        """
        Use snKey()
        Return list of out of order escrow event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.ooes, key)

    def getOoeLast(self, key):
        """
        Use snKey()
        Return last inserted dup val of out of order escrow event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.ooes, key)

    def getOoeItemIter(self, key=b''):
        """
        Use sgKey()
        Return iterator of out of order escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getTopIoDupItemIter(self.ooes, key)
        #return self.getIoDupItemsNextIter(self.ooes, key, skip)

    def cntOoes(self, key):
        """
        Use snKey()
        Return count of dup event dig at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.ooes, key)

    def delOoes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoDupVals(self.ooes, key)

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
        return self.delIoDupVal(self.ooes, key, val)


    def putDes(self, key, vals):
        """
        Use snKey()
        Write each duplicitous event entry dig from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoDupVals(self.dels, key, vals)

    def addDe(self, key, val):
        """
        Use snKey()
        Add duplicate event index val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.dels, key, val)

    def getDes(self, key):
        """
        Use snKey()
        Return list of duplicitous event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.dels, key)

    def getDeLast(self, key):
        """
        Use snKey()
        Return last inserted dup value of duplicitous event dig vals at key
        Returns None if no entry at key

        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.dels, key)

    def cntDes(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.dels, key)

    def delDes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoDupVals(self.dels, key)

    def getDelItemIter(self, pre):
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
        return self.getTopIoDupItemIter(self.dels, pre)
        #return self.getOnIoDupValsAnyPreIter(self.dels, pre)

    def putLdes(self, key, vals):
        """
        Use snKey()
        Write each likely duplicitous event entry dig from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoDupVals(self.ldes, key, vals)

    def addLde(self, key, val):
        """
        Use snKey()
        Add likely duplicitous escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoDupVal(self.ldes, key, val)

    def getLdes(self, key):
        """
        Use snKey()
        Return list of likely duplicitous event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupVals(self.ldes, key)

    def getLdeLast(self, key):
        """
        Use snKey()
        Return last inserted dup val of likely duplicitous event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoDupValLast(self.ldes, key)

    def getLdeItemIter(self, key=b''):
        """
        Use sgKey()
        Return iterator of likely duplicitous escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getTopIoDupItemIter(self.ldes, key)
        #return self.getIoDupItemsNextIter(self.ldes, key, skip)

    def cntLdes(self, key):
        """
        Use snKey()
        Return count of dup event dig at key
        Returns zero if no entry at key
        """
        return self.cntIoDupVals(self.ldes, key)

    def delLdes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoDupVals(self.ldes, key)

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
        return self.delIoDupVal(self.ldes, key, val)


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
