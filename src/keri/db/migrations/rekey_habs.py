from dataclasses import dataclass, field, asdict

from keri.db import koming, basing


@dataclass
class OldHabitatRecord:  # baser.habs
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


def migrate(db):
    """ Re-key habs migration for changing the key for .habs and introducing the .names database

    This migrations performs the following:
    1.  Rekey .habs from name (alias) to the AID of the Hab
    2.  Add Name and domain to the HabitatRecord for all Habs
    3.  Populate the .names index as (ns, name) -> AID
    4.  Remove the .nmsp namespaced Habs database (replaced within .habs and .names now)

    Parameters:
        db(Baser): Baser database object on which to run the migration

    """
    habs = koming.Komer(db=db,
                        subkey='habs.',
                        schema=OldHabitatRecord, )

    # habitat application state keyed by habitat namespace + b'\x00' + name, includes prefix
    nmsp = koming.Komer(db=db,
                        subkey='nmsp.',
                        schema=OldHabitatRecord, )

    habords = dict()
    # Update Hab records from .habs with name
    for name, habord in habs.getItemIter():
        name = ".".join(name)  # detupleize the database key name
        nhabord = basing.HabitatRecord(**asdict(habord))
        nhabord.name = name
        habords[habord.hid] = nhabord

    habs.trim()

    # Update Hab records from .nmsp with name and domain (ns)
    for keys, habord in nmsp.getItemIter():
        ns = keys[0]
        name = ".".join(keys[1:])  # detupleize the database key name
        nhabord = basing.HabitatRecord(**asdict(habord))
        nhabord.name = name
        nhabord.domain = ns
        habords[habord.hid] = nhabord

    nmsp.trim()  # remove existing records

    # Rekey .habs and create .names index
    for pre, habord in habords.items():
        db.habs.pin(keys=(pre,), val=habord)
        ns = "" if habord.domain is None else habord.domain
        db.names.pin(keys=(ns, habord.name), val=pre)
