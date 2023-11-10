# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json
from collections import namedtuple
from dataclasses import field, asdict, dataclass
from math import ceil

from ordered_set import OrderedSet as oset
import cbor2 as cbor
import msgpack

from hio import help
from hio.base import doing

from keri import kering
from keri.app.cli.common import existing
from keri.core import coring, eventing
from keri.core.coring import Serials, Number, Ilks, Tholder
from keri.core.eventing import MaxIntThold, TraitDex, ample
from keri.db import koming, dbing, subing
from keri.help import helping
from keri.kering import ConfigurationError, Version

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='View status of a local AID')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--force', action="store_true", required=False,
                    help='True means perform migration without prompting the user')

StateEstEvent = namedtuple("StateEstEvent", 's d br ba')

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
        vn (list[int]): version list [major, minor]
        i (str): identifier prefix qb64
        s (str): sequence number of latest event in KEL as hex str
        p (str): prior event digest qb64
        d (str): latest event digest qb64
        f (str): first seen ordinal number of latest event in KEL as hex str
        dt (str): datetime iso-8601
        et (str): latest establishment event packet type
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
        di (str): delegator aid qb64


    """
    vn: list[int] = field(default_factory=list)  # version number [major, minor] round trip serializable
    i: str =''  # identifier prefix qb64
    s: str ='0'  # sequence number of latest event in KEL as hex str
    p: str =''  # prior event digest qb64
    d: str =''  # latest event digest qb64
    f: str ='0'  # first seen ordinal number of latest event in KEL as hex str
    dt: str = ''  # datetime of creation of state
    et: str = ''  # latest est evt packet type (ilk)
    kt: str = '0'  # signing threshold sith
    k: list[str] = field(default_factory=list)  # signing key list qb64
    nt: str =  '0'  # next rotation threshold nsith
    n: list[str] =  field(default_factory=list) #  next rotation key digest list qb64
    bt: str = '0'  # backer threshold hex num str
    b: list = field(default_factory=list)  # backer AID list qb64
    c: list[str] =  field(default_factory=list)  # config trait list
    ee: StateEERecord = field(default_factory=StateEERecord)

    #field(default_factory=dict) # latest est event details
    # asdict of StateEstEvent
    # s = sn of latest est event as lowercase hex string  no leading zeros,
    # d = SAID digest qb64  of latest establishment event
    # br = backer (witness) remove list (cuts) from latest est event
    # ba = backer (witness) add list (adds) from latest est event
    di: str = '' # delegator aid qb64 if any otherwise empty '' str


def handler(args):
    if not args.force:
        print()
        print("This command will migrate your datastore to the next version of KERIpy and is not reversible.")
        print("After this command, you will not be able to access your data store with this version.")
        print()
        yn = input("Are you sure you want to continue? [y|N]: ")

        if yn not in ("y", "Y"):
            print("...exiting")
            return []

    kwa = dict(args=args)
    return [doing.doify(migrate, **kwa)]


def migrate(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:

            states = koming.Komer(db=hby.db,
                                  schema=KeyStateRecord,
                                  subkey='stts.')

            for _, stt in hby.db.states.getItemIter():
                kever = eventing.Kever(state=stt, db=hby.db)
                ksr = stateFromKever(kever)
                states.pin(kever.prefixer.qb64, val=ksr)

            migrateKeys(hby)

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

def stateFromKever(kever):
    """
    Returns KeyStateRecord instance of current key state

    """
    eevt = StateEstEvent(s="{:x}".format(kever.lastEst.s),
                         d=kever.lastEst.d,
                         br=kever.cuts,
                         ba=kever.adds)

    cnfg = []
    if kever.estOnly:
        cnfg.append(TraitDex.EstOnly)
    if kever.doNotDelegate:
        cnfg.append(TraitDex.DoNotDelegate)

    return (state(pre=kever.prefixer.qb64,
                  sn=kever.sn,  # property self.sner.num
                  pig=(kever.serder.ked["p"] if "p" in kever.serder.ked else ""),
                  dig=kever.serder.said,
                  fn=kever.fn,  # property self.fner.num
                  stamp=kever.dater.dts,  # need to add dater object for first seen dts
                  eilk=kever.ilk,
                  keys=[verfer.qb64 for verfer in kever.verfers],
                  eevt=eevt,
                  sith=kever.tholder.sith,
                  nsith=kever.ntholder.sith if kever.ntholder else '0',
                  ndigs=[diger.qb64 for diger in kever.digers],
                  toad=kever.toader.num,
                  wits=kever.wits,
                  cnfg=cnfg,
                  dpre=kever.delegator,
                  )
            )



def state(pre,
          sn,
          pig,
          dig,
          fn,
          eilk,
          keys,
          eevt,
          stamp=None,  # default current datetime
          sith=None,  # default based on keys
          ndigs=None,
          nsith=None,
          toad=None,  # default based on wits
          wits=None,  # default to []
          cnfg=None,  # default to []
          dpre=None,
          version=Version,
          kind=Serials.json,
          intive = False,
          ):
    """
    Returns serder of key state notification message.
    Utility function to automate creation of rotation events.

    Parameters:
        pre (str): identifier prefix qb64
        sn (int): sequence number of latest event
        pig (str): SAID qb64 of prior event
        dig (str): SAID qb64 of latest (current) event
        fn (int):  first seen ordinal number of latest event
        eilk (str): event (message) type (ilk) of latest (current) event
        keys (list): qb64 signing keys
        eevt (StateEstEvent): namedtuple (s,d,wr,wa) for latest est event
            s = sn of est event
            d = SAID of est event
            wr = witness remove list (cuts)
            wa = witness add list (adds)
        stamp (str | None):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                      creation of message or data
        sith sith (int | str | list | None): current signing threshold input to Tholder
        ndigs (list | None): current signing key digests qb64
        nsith int | str | list | None): next signing threshold input to Tholder
        toad (int | str | None): witness threshold number if str then hex str
        wits (list | None): prior witness identifier prefixes qb64
        cnfg (list | None):  strings from TraitDex configuration trait strings
        dpre (str | None): identifier prefix qb64 delegator if any
                           If None then dpre in state is empty ""
        version (Version): KERI protocol version string
        kind (str): serialization kind from Serials
        intive (bool): True means sith, nsith, and toad are serialized as ints
                       instead of hex str when numeric threshold

    KeyStateDict:
    {
        #"v": "KERI10JSON00011c_",
        "vn": []1,0],
        "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
        "s": "2":,
        "p": "EYAfSVPzhzZ-i0d8JZS6b5CMAoTNZH3ULvaU6JR2nmwy",
        "d": "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
        "f": "3",
        "dt": "2020-08-22T20:35:06.687702+00:00",
        "et": "rot",
        "kt": "1",
        "k": ["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],
        "nt": "1",
        "n": "EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
        "bt": "1",
        "b": ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"],
        "c": ["EO"],
        "ee":
          {
            "s": "1",
            "d": "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
            "br": ["Dd8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CMZ-i0"],
            "ba": ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"]
          },
        "di": "EYAfSVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULv",
    }

    "di": "" when not delegated
    """
    #vs = versify(version=version, kind=kind, size=0)

    sner = Number(num=sn)  # raises InvalidValueError if sn < 0

    fner = Number(num=fn)  # raises InvalidValueError if fn < 0

    if eilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt):
        raise ValueError(f"Invalid event type et={eilk} in key state.")

    if stamp is None:
        stamp = helping.nowIso8601()

    if sith is None:
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.num is not None and tholder.num < 1:
        raise ValueError(f"Invalid sith = {tholder.num} less than 1.")
    if tholder.size > len(keys):
        raise ValueError(f"Invalid sith = {tholder.num} for keys = {keys}")

    if ndigs is None:
        ndigs = []

    if nsith is None:
        nsith = max(0, ceil(len(ndigs) / 2))

    ntholder = Tholder(sith=nsith)
    if ntholder.num is not None and ntholder.num < 0:
        raise ValueError(f"Invalid nsith = {ntholder.num} less than 0.")
    if ntholder.size > len(ndigs):
        raise ValueError(f"Invalid nsith = {ntholder.num} for keys = {ndigs}")

    wits = wits if wits is not None else []
    witset = oset(wits)
    if len(witset) != len(wits):
        raise ValueError(f"Invalid wits = {wits}, has duplicates.")

    if toad is None:
        if not witset:
            toad = 0
        else:
            toad = max(1, ceil(len(witset) / 2))

    if toad is None:
        if not witset:
            toad = 0
        else:  # compute default f and m for len(wits)
            toad = ample(len(witset))
    toader = Number(num=toad)

    if witset:
        if toader.num < 1 or toader.num > len(witset):  # out of bounds toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {witset}")
    else:
        if toader.num != 0:  # invalid toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {witset}")

    if not eevt or not isinstance(eevt, StateEstEvent):
        raise ValueError(f"Missing or invalid latest est event = {eevt} for key "
                         f"state.")
    eesner = Number(numh=eevt.s)  # if not whole number raises InvalidValueError

    # cuts is relative to prior wits not current wits provided here
    cuts = eevt.br if eevt.br is not None else []
    cutset = oset(cuts)
    if len(cutset) != len(cuts):  # duplicates in cuts
        raise ValueError(f"Invalid cuts = {cuts}, has "
                         f"duplicates, in latest est event, .")

    # adds is relative to prior wits not current wits provided here
    adds = eevt.ba if eevt.ba is not None else []
    addset = oset(adds)

    if len(addset) != len(adds):  # duplicates in adds
        raise ValueError(f"Invalid adds = {adds}, has duplicates,"
                         f" in latest est event,.")

    if cutset & addset:  # non empty intersection
        raise ValueError(f"Intersecting cuts = {cuts} and adds = {adds} in "
                         f"latest est event.")

    ksr = KeyStateRecord(
        vn=list(version), # version number as list [major, minor]
        i=pre,  # qb64 prefix
        s=sner.numh,  # lowercase hex string no leading zeros
        p=pig,
        d=dig,
        f=fner.numh,  # lowercase hex string no leading zeros
        dt=stamp,
        et=eilk,
        kt=(tholder.num if intive and tholder.num is not None and
                           tholder.num <= MaxIntThold else tholder.sith),
        k=keys,  # list of qb64
        nt=(ntholder.num if intive and ntholder.num is not None and
                            ntholder.num <= MaxIntThold else ntholder.sith),
        n=ndigs,
        bt=toader.num if intive and toader.num <= MaxIntThold else toader.numh,
        b=wits,  # list of qb64 may be empty
        c=cnfg if cnfg is not None else [],
        ee=StateEERecord._fromdict(eevt._asdict()),  # latest est event dict
        di=dpre if dpre is not None else "",
    )
    return ksr  # return KeyStateRecord  use asdict(ksr) to get dict version


def migrateKeys(hby):
    # public keys mapped to the AID and event seq no they appeared in
    pubs = subing.CatCesrIoSetSuber(db=hby.db, subkey="pubs.",
                                    klas=(coring.Prefixer, coring.Seqner))

    # next key digests mapped to the AID and event seq no they appeared in
    digs = subing.CatCesrIoSetSuber(db=hby.db, subkey="digs.",
                                    klas=(coring.Prefixer, coring.Seqner))

    for pre, fn, dig in hby.db.getFelItemAllPreIter(key=b''):
        dgkey = dbing.dgKey(pre, dig)  # get message
        if not (raw := hby.db.getEvt(key=dgkey)):
            raise kering.MissingEntryError("Missing event for dig={}.".format(dig))
        serder = coring.Serder(raw=bytes(raw))
        val = (coring.Prefixer(qb64b=serder.preb), coring.Seqner(sn=serder.sn))
        for verfer in serder.verfers:
            pubs.add(keys=(verfer.qb64,), val=val)
        for diger in serder.digers:
            digs.add(keys=(diger.qb64,), val=val)
