# -*- encoding: utf-8 -*-
"""
KERI
keri.recording module

Shared record and dataclass types.
"""
from dataclasses import dataclass, asdict, field
import json

import cbor2 as cbor
import msgpack

from .help import helping


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

