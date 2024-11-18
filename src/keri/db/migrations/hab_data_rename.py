from dataclasses import dataclass, field, asdict
from typing import Optional

from keri.db import koming, basing
from keri.db.basing import HabitatRecord, Baser
from keri.vdr.viring import Reger


@dataclass
class HabitatRecordV0_6_7:  # baser.habs
    """
    Habitat application state information keyed by habitat name (baser.habs)

    Attributes:
        prefix (str): identifier prefix of hab qb64
        pid (str | None): group member identifier qb64 when hid is group
        aids (list | None): group signing member identifiers qb64 when hid is group
        watchers: (list[str]) = list of id prefixes qb64 of watchers
    """
    prefix: str  # aid qb64
    pid: Optional[str]  # participant aid of group aid
    aids: Optional[list]  # all identifiers participating in the group identity

    watchers: list[str] = field(default_factory=list)  # aids qb64 of watchers

@dataclass
class HabitatRecordV0_6_8:  # baser.habs
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
    mid: str | None = None  # group member identifier qb64 when hid is group
    smids: list | None = None  # group signing member ids when hid is group
    rmids: list | None = None  # group rotating member ids when hid is group
    sid: str | None = None  # Signify identifier qb64 when hid is Signify
    watchers: list[str] = field(default_factory=list)  # id prefixes qb64 of watchers

def _check_if_needed(db):
    """
    Check if the migration is needed
    Parameters:
        db(Baser): Baser database object on which to run the migration
    Returns:
        bool: True if the migration is needed, False otherwise
    """
    habs = koming.Komer(db=db, subkey='habs.', schema=dict, )
    first = next(habs.getItemIter(), None)
    if first is None:
        return False
    name, habord = first
    if 'prefix' in habord:
        return True
    return False

def migrate(db):
    """Rename data in HabitatRecord from the old labels to the new labels as of 2022-10-17

    This migration performs the following:
    1.  rename prefix -> hid
    2.  rename pid -> mid
    3.  rename aids -> smids, rmids

    Parameters:
        db(Baser): Baser database object on which to run the migration
    """
    # May be running on a database that is already in the right state yet has no migrations run
    # so we need to check if the migration is needed
    if not _check_if_needed(db):
        print(f"{__name__} migration not needed, database already in correct state")
        return

    habs = koming.Komer(db=db,
                        subkey='habs.',
                        schema=HabitatRecordV0_6_7, )

    habords = dict()
    # Update Hab records from .habs with name
    for name, habord in habs.getItemIter():
        existing = asdict(habord)
        habord_0_6_7 = HabitatRecordV0_6_7(**existing)
        habord_0_6_8 = HabitatRecordV0_6_8(
            hid=habord_0_6_7.prefix,
            mid=habord_0_6_7.pid,
            smids=habord_0_6_7.aids,
            rmids=habord_0_6_7.aids,
            sid=None,
            watchers=habord_0_6_7.watchers
        )
        habords[name] = habord_0_6_8

    habs.trim() # remove existing records

    # Add in the renamed records
    habs = koming.Komer(db=db,
                        subkey='habs.',
                        schema=HabitatRecordV0_6_8, )

    for name, habord in habords.items():
        name, = name
        habs.pin(keys=(name,), val=habord)
