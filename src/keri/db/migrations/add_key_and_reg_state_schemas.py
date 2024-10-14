from keri import help
from keri.core import coring, serdering
from keri.db import koming, subing, dbing
from keri.db.basing import StateEERecord, KeyStateRecord
from keri.db.dbing import dgKey, splitKey
from keri.kering import ConfigurationError, Version
from keri.vdr import viring

logger = help.ogler.getLogger()

def _check_if_needed(db):
    states = koming.Komer(db=db,
                          schema=dict,
                          subkey='stts.')
    first = next(states.getItemIter(), None)
    if first is None:
        return False
    keys, sad = first
    if 'vn' in sad:
        return False
    return True

def migrate(db):
    """Adds schema for KeyStateRecord, RegStateRecord, and migrates the rgy.cancs., hby.db.pubs.,
    and hby.db.digs. to be up to date as of 2022-??-??
    This migration performs the following:
    - hby.db -> "stts."  schema from dict -> KeyStateRecord
    -    rgy -> "stts."  schema from dict -> RegStateRecord
    -    rgy -> "cancs." reset to (ACDC SAID, SN 0, TEL evt 0 digest)
    - hby.db -> "pubs." and
      hby.db -> "digs."
      that don't exist are populated with verification keys and event digests for the first seen events and
        Keys:
           "pubs." Verfer of each Verfer for each FEL event
           "digs." Diger of next Diger (ndiger) of each FEL event
        Value: (prefix, sn) of each event
    Parameters:
        db(Baser): Baser database object on which to run the migration
    """
    # May be running on a database that is already in the right state yet has no migrations run
    # so we need to check if the migration is needed
    if not _check_if_needed(db):
        print(f"{__name__} migration not needed, database already in correct state")
        return

    try:
        logger.debug(f"Migrating keystate and regstate dict to schema for {db.path}")
        states = koming.Komer(db=db,
                              schema=dict,
                              subkey='stts.')
        nstates = koming.Komer(db=db,
                               schema=KeyStateRecord,
                               subkey='stts.')

        for keys, sad in states.getItemIter():
            ksr = KeyStateRecord(
                vn=Version,  # version number as list [major, minor]
                i=sad['i'],  # qb64 prefix
                s=sad['s'],  # lowercase hex string no leading zeros
                p=sad['p'],
                d=sad['d'],
                f=sad['f'],  # lowercase hex string no leading zeros
                dt=sad['dt'],
                et=sad['et'],
                kt=sad['kt'],
                k=sad['k'],
                nt=sad['nt'],
                n=sad['n'],
                bt=sad['bt'],
                b=sad['b'],
                c=sad['c'],
                ee=StateEERecord._fromdict(sad['ee']),  # latest est event dict
                di=sad['di'] if sad['di'] else None
            )

            nstates.pin(keys=keys, val=ksr)

        rgy = viring.Reger(name=db.name, base=db.base, db=db, temp=db.temp, reopen=True)

        rstates = koming.Komer(db=rgy,
                               schema=dict,
                               subkey='stts.')

        for _, sad in rstates.getItemIter():
            rsr = viring.RegStateRecord(
                vn=list(Version),  # version number as list [major, minor]
                i=sad['i'],  # qb64 registry SAID
                s=sad['s'],  # lowercase hex string no leading zeros
                d=sad['d'],
                ii=sad['ii'],
                dt=sad['dt'],
                et=sad['et'],
                bt=sad['bt'],  # hex string no leading zeros lowercase
                b=sad['b'],  # list of qb64 may be empty
                c=sad['c'],
            )
            # ksr = stateFromKever(kever)
            rgy.states.pin(sad['i'], val=rsr)

        for (said,), _ in rgy.saved.getItemIter():
            snkey = dbing.snKey(said, 0)
            dig = rgy.getTel(key=snkey)

            prefixer = coring.Prefixer(qb64=said)
            seqner = coring.Seqner(sn=0)
            saider = coring.Saider(qb64b=bytes(dig))
            rgy.cancs.pin(keys=said, val=[prefixer, seqner, saider])

        migrateKeys(db)

        # clear escrows
        logger.info("clearing escrows")
        db.gpwe.trim()
        db.gdee.trim()
        db.dpwe.trim()
        db.gpse.trim()
        db.epse.trim()
        db.dune.trim()
        db.qnfs.trim()

    except ConfigurationError:
        logger.error(f"identifier prefix for {db.name} does not exist, incept must be run first", )
        return -1


def migrateKeys(db):
    # public keys mapped to the AID and event seq no they appeared in
    pubs = subing.CatCesrIoSetSuber(db=db, subkey="pubs.",
                                    klas=(coring.Prefixer, coring.Seqner))

    # next key digests mapped to the AID and event seq no they appeared in
    digs = subing.CatCesrIoSetSuber(db=db, subkey="digs.",
                                    klas=(coring.Prefixer, coring.Seqner))

    for pre, fn, dig in db.getFelItemAllPreIter():
        dgkey = dbing.dgKey(pre, dig)  # get message
        if not (raw := db.getEvt(key=dgkey)):
            logger.info(f"Migrate keys: missing event for dig={dig}, skipped.")
            continue
        serder = serdering.SerderKERI(raw=bytes(raw))
        val = (coring.Prefixer(qb64b=serder.preb), coring.Seqner(sn=serder.sn))
        verfers = serder.verfers or []
        for verfer in verfers:
            pubs.add(keys=(verfer.qb64,), val=val)
        ndigers = serder.ndigers or []
        for diger in ndigers:
            digs.add(keys=(diger.qb64,), val=val)