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
    habs = koming.Komer(db=db,
                        subkey='habs.',
                        schema=OldHabitatRecord, )

    # habitat application state keyed by habitat namespace + b'\x00' + name, includes prefix
    nmsp = koming.Komer(db=db,
                        subkey='nmsp.',
                        schema=OldHabitatRecord, )

    habords = dict()
    for name, habord in habs.getItemIter():
        name = ".".join(name)  # detupleize the database key name
        nhabord = basing.HabitatRecord(**asdict(habord))
        nhabord.name = name
        habords[habord.hid] = nhabord

    habs.trim()

    for keys, habord in nmsp.getItemIter():
        ns = keys[0]
        name = ".".join(keys[1:])  # detupleize the database key name
        nhabord = basing.HabitatRecord(**asdict(habord))
        nhabord.name = name
        nhabord.domain = ns
        habords[habord.hid] = nhabord

    nmsp.trim()

    for pre, habord in habords.items():
        print(pre)
        print(habord)
        db.habs.pin(keys=(pre,), val=habord)
        ns = "" if habord.domain is None else habord.domain
        print(ns)
        print(habord.name)
        db.names.pin(keys=(ns, habord.name), val=pre)
