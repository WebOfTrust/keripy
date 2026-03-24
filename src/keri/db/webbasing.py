# -*- encoding: utf-8 -*-
"""
keri.db.webbasing module

Browser-safe plain-value DBer backed by PyScript storage.
"""

from __future__ import annotations

import semver
import importlib
from collections import namedtuple

from hio.help import ogler

from ordered_set import OrderedSet as oset

from keri import __version__

from ..recording import (KeyStateRecord, EventSourceRecord,
                         HabitatRecord)

from ..kering import (MissingEntryError, ValidationError,
                      ConfigurationError, Vrsn_1_0)

from .dbing import dgKey
from .basing import MIGRATIONS, _strip_prerelease
from .webdbing import WebDBer, statedict

try:
    import js 
except ImportError:  # pragma: no cover
    storage = None
    js = None

logger = ogler.getLogger()

# The following are necessary to define in this file 
# to prevent non wasm compatible imports (importing from dbing)
# MaxON, onKey, splitKey, splitOnKey

MaxON = int("f"*32, 16)  # max ordinal number, same as kering.MaxON

class WebBaser(WebDBer):
    def __init__(self, name="main", reopen=False, **kwa):
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
        SubDbNames = [
            "evts.", "sigs.", "wigs.", "dtss.", "aess.", "rcts.", "vrcs.", "vres.",
            "kels.", "fels.", "ooes.", "pses.", "dels.", "ldes.", "pdes.", "pwes.",
            "ures.", "esrs.", "states.", "habs.", "names.", "udes.",
            "imgs.", "iimgs.",
        ]
        self.SubDbNames = SubDbNames

        self.prefixes = oset()  # should change to hids for hab ids
        self.groups = oset()  # group hab ids
        self._kevers = statedict()
        self._kevers.db = self  # assign db for read through cache of kevers

        self.name = name
        self.opened = False

        # Store reopen flag (async)
        self._should_reopen = reopen

    @property
    def kevers(self):
        """
        Returns .db.kevers
        """
        return self._kevers

    async def reopen(self, clear=False, storageOpener=None):
        self.db = await WebDBer.open(
            name=self.name,
            stores=self.SubDbNames,
            clear=clear,
            storageOpener=storageOpener,
        )

        self.env = self.db.env

        self._bindSubDbs()
        self.reload()
        self.opened = True


    async def close(self, *, clear: bool = False):
            """
            Flush pending writes and optionally clear backing storage.

            In a browser environment, "clear" is typically used only for tests or
            explicit reset flows.
            """

            if not self.opened or self.db is None:
                return

            await self.db.flush()

            if clear:
                await self._clearIndexedDB()

            self.db = None
            self.env = None
            self.opened = False

    
    async def _clearIndexedDB(self):
        """
        Clear all backing storage namespaces for this baser.

        Each SubDb in WebDBer has a `handle` that behaves like a dict-like
        IndexedDB wrapper. Clearing the handle removes all persisted records.
        """
        if self.db is None:
            return

        # Clear each store's persisted payload
        for subdb in self.db._stores.values():
            handle = subdb.handle
            handle.clear()        # remove all keys from IndexedDB
            await handle.sync()   # persist the deletion


    def _bindSubDbs(self):
        from . import koming, subing
        from ..core import coring, indexing

        self.evts = subing.SerderSuber(db=self, subkey='evts.')
        self.sigs = subing.CesrIoSetSuber(db=self, subkey='sigs.', klas=(indexing.Siger))
        self.wigs = subing.CesrIoSetSuber(db=self, subkey='wigs.', klas=(indexing.Siger))
        self.dtss = subing.CesrSuber(db=self, subkey='dtss.', klas=coring.Dater)
        self.aess = subing.CatCesrSuber(db=self, subkey='aess.', klas=(coring.Number, coring.Diger))
        self.rcts = subing.CatCesrIoSetSuber(db=self, subkey='rcts.',
                                            klas=(coring.Prefixer, coring.Cigar))
        self.vrcs = subing.CatCesrIoSetSuber(db=self, subkey='vrcs.',
                                            klas=(coring.Prefixer, coring.Number, coring.Diger, indexing.Siger))
        self.vres = subing.CatCesrIoSetSuber(db=self, subkey='vres.',
                        klas=(coring.Diger, coring.Prefixer, coring.Number, coring.Diger, indexing.Siger))
        self.kels = subing.OnIoSetSuber(db=self, subkey='kels.')
        self.fels = subing.OnSuber(db=self, subkey='fels.')
        self.ooes = subing.OnIoSetSuber(db=self, subkey='ooes.')
        self.pses = subing.OnIoSetSuber(db=self, subkey='pses.')
        self.pwes = subing.OnIoSetSuber(db=self, subkey='pwes.')
        self.pdes = subing.OnIoSetSuber(db=self, subkey='pdes.')
        self.udes = subing.CatCesrSuber(db=self, subkey='udes.', klas=(coring.Number, coring.Diger))
        self.dels = subing.OnIoSetSuber(db=self, subkey='dels.')
        self.ldes = subing.OnIoSetSuber(db=self, subkey='ldes.')
        self.ures = subing.CatCesrIoSetSuber(db=self, subkey='ures.',
                                            klas=(coring.Diger, coring.Prefixer, coring.Cigar))

        self.esrs = koming.Komer(db=self, subkey='esrs.', klas=EventSourceRecord)
        self.states = koming.Komer(db=self, subkey='states.', klas=KeyStateRecord)
        self.habs = koming.Komer(db=self, subkey='habs.', klas=HabitatRecord)
        self.names = subing.Suber(db=self, subkey='names.', sep="^")

        self.imgs = subing.CesrSuber(db=self, subkey='imgs.')
        self.iimgs = subing.CesrSuber(db=self, subkey='iimgs.')


    def reload(self):
        self.prefixes.clear()
        self.groups.clear()
        self._kevers.clear()

        for keys, hab in self.habs.getTopItemIter():
            state = self.states.get(keys=hab.hid)
            if state is None:
                continue

            try:
                from ..core.eventing import Kever
                kever = Kever(state=state, db=self, local=True)
            except Exception:
                continue

            self._kevers[kever.prefixer.qb64] = kever
            self.prefixes.add(kever.prefixer.qb64)

            if hab.mid:
                self.groups.add(hab.hid)


    
    def migrate(self):
        """ Run all migrations required

        Run all migrations  that are required from the current version of database up to the current version
         of the software that have not already been run.

         Sets the version of the database to the current version of the software after successful completion
         of required migrations

        """
        from ..core import coring

        escrows_cleared = False

        for (version, migrations) in MIGRATIONS:
            # Only run migration if current source code version is at or below the migration version
            ver = semver.VersionInfo.parse(__version__)
            ver_no_prerelease = semver.Version(ver.major, ver.minor, ver.patch)
            if self.version is not None and semver.compare(version, str(ver_no_prerelease)) > 0:
                print(
                    f"Skipping migration {version} as higher than the current KERI version {__version__}")
                continue
            # Skip migrations already run - where version less than (-1) or equal to (0) database version
            # Strip prerelease from DB version to avoid lexicographic comparison bugs (#820)
            if self.version is not None and semver.compare(version, _strip_prerelease(self.version)) != 1:
                continue

            # Clear all escrows before first migration to prevent old key
            # format crashes (e.g. qnfs keys without insertion-order suffix).
            # Uses .trim() which bypasses key parsing. See #863.
            if not escrows_cleared:
                self._trimAllEscrows()
                escrows_cleared = True

            print(f"Migrating database v{self.version} --> v{version}")
            for migration in migrations:
                modName = f"keri.db.migrations.{migration}"
                if self.migs.get(keys=(migration,)) is not None:
                    continue

                mod = importlib.import_module(modName)
                try:
                    print(f"running migration {modName}")
                    mod.migrate(self)
                except Exception as e:
                    print(f"\nAbandoning migration {migration} at version {version} with error: {e}")
                    return

                self.migs.pin(keys=(migration,), val=coring.Dater())

            # update database version after successful migration
            self.version = version

        self.version = __version__

    
    def _trimAllEscrows(self):
        """Trim all escrow databases via low-level .trim().

        Safe for old key formats that would crash higher-level iterators
        (e.g., qnfs keys without insertion-order suffix from pre-1.2.0).
        Called at the beginning of migration per spec call guidance.
        See: https://github.com/WebOfTrust/keripy/issues/863
        """
        escrows = [
            self.ures, self.vres, self.pses, self.pwes, self.ooes,
            self.qnfs, self.uwes, self.misfits, self.delegables,
            self.pdes, self.udes, self.rpes, self.ldes, self.epsd,
            self.eoobi, self.dpub, self.gpwe, self.gdee, self.dpwe,
            self.gpse, self.epse, self.dune,
        ]
        total = 0
        for escrow in escrows:
            count = escrow.cnt()
            if count > 0:
                escrow.trim()
                total += count
        if total > 0:
            print(f"Cleared {total} escrow entries before migration")

    def clearEscrows(self):
        """
        Clear all escrows
        """
        for escrow in [self.ures, self.vres, self.pses, self.pwes, self.ooes,
                       self.qnfs, self.uwes,
                       self.qnfs, self.misfits, self.delegables, self.pdes,
                       self.udes, self.rpes, self.ldes, self.epsd, self.eoobi,
                       self.dpub, self.gpwe, self.gdee, self.dpwe, self.gpse,
                       self.epse, self.dune]:
            count = escrow.cntAll()
            escrow.trim()
            logger.info(f"KEL: Cleared {count} escrows from ({escrow}")

    @property
    def current(self):
        """ Current property determines if we are at the current database migration state.

         If the database version matches the library version return True
         If the current database version is behind the current library version, check for migrations
            - If there are migrations to run, return False
            - If there are no migrations to run, reset database version to library version and return True
         If the current database version is ahead of the current library version, raise exception

         """
        if self.version == __version__:
            return True

        ver = semver.VersionInfo.parse(__version__)
        ver_no_prerelease = semver.Version(ver.major, ver.minor, ver.patch)
        # Strip prerelease from DB version to avoid lexicographic comparison bugs (#820)
        if self.version is not None and semver.compare(_strip_prerelease(self.version), str(ver_no_prerelease)) == 1:
            raise ConfigurationError(
                f"Database version={self.version} is ahead of library version={__version__}")

        last = MIGRATIONS[-1]
        # If we aren't at latest version, but there are no outstanding migrations,
        # reset version to latest (rightmost (-1) migration is latest)
        if self.migs.get(keys=(last[1][-1],)) is not None:
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
                # Print entries only for migrations that have been run
                # Strip prerelease from DB version to avoid lexicographic comparison bugs (#820)
                if self.version is not None and semver.compare(version, _strip_prerelease(self.version)) <= 0:
                    for mig in migs:
                        dater = self.migs.get(keys=(mig,))
                        migrations.append((mig, dater))
        else:
            for version, migs in MIGRATIONS:  # check all migrations for each version
                if name not in migs or not self.migs.get(keys=(name,)):
                    raise ValueError(f"No migration named {name}")
            migrations.append((name, self.migs.get(keys=(name,))))

        return migrations
    
    async def _replaceIndexedDB(self, clean):
        """
        Replace this WebBaser's IndexedDB database with the clean clone.

        Steps:
        1. Close both DBs
        2. Delete the old IndexedDB database
        3. Rename the clean DB to the original name
        4. Reopen this WebBaser
        """

        old_name = self.name
        new_name = clean.name

        # 1. Close both DBs (flush + close IDB connections)
        await self.close()
        await clean.close()

        # 2. Delete the old IndexedDB database
        #    Equivalent to LMDB's: rm -rf old
        delete_req = js.indexedDB.deleteDatabase(old_name)
        await delete_req

        # 3. Rename clean DB to original name
        #    IndexedDB has no rename primitive, so we:
        #    - open clean DB under old_name
        #    - copy all object stores
        #    - delete the clean DB
        open_req = js.indexedDB.open(new_name)
        clean_db = await open_req

        # Create new DB under old_name
        open_req2 = js.indexedDB.open(old_name)
        new_db = await open_req2

        # Copy all object stores from clean_db → new_db
        for store_name in clean_db.objectStoreNames:
            if store_name not in new_db.objectStoreNames:
                version = new_db.version + 1
                new_db.close()
                upgrade_req = js.indexedDB.open(old_name, version)
                new_db = await upgrade_req
                new_db.createObjectStore(store_name)

            tx_src = clean_db.transaction(store_name, "readonly")
            tx_dst = new_db.transaction(store_name, "readwrite")

            src_store = tx_src.objectStore(store_name)
            dst_store = tx_dst.objectStore(store_name)

            get_all_req = src_store.getAll()
            values = await get_all_req

            get_keys_req = src_store.getAllKeys()
            keys = await get_keys_req

            for key, val in zip(keys, values):
                dst_store.put(val, key)

            await tx_dst.done

        clean_db.close()

        # Delete the temporary clean DB
        delete_clean_req = js.indexedDB.deleteDatabase(new_name)
        await delete_clean_req

        # 4. Reopen this WebBaser using the new DB
        await self.reopen()

    async def clean(self):
        """
        Clean WebDB database by cloning into a new WebBaser instance,
        reprocessing events, copying non-event subdbs, and replacing
        the old IndexedDB database.
        """

        from ..core import parsing
        from ..core.eventing import Kevery

        # -------------------------------------------------------------
        # 1. Create a fresh empty WebBaser clone
        # -------------------------------------------------------------
        clean_name = f"{self.name}_clean"
        copy = WebBaser(name=clean_name, headDirPath=self.headDirPath)

        # -------------------------------------------------------------
        # 2. Replay all events into the clean DB
        # -------------------------------------------------------------
        kvy = Kevery(db=copy)
        psr = parsing.Parser(kvy=kvy, version=Vrsn_1_0)

        for msg in self.cloneAllPreIter():
            psr.parseOne(ims=msg)

        # -------------------------------------------------------------
        # 3. Copy non-event subdbs (same logic as LMDB version)
        # -------------------------------------------------------------
        unsecured = [
            "hbys", "schema", "states", "rpys", "eans", "tops", "cgms", "exns",
            "erpy", "kdts", "ksns", "knas", "oobis", "roobi", "woobi", "moobi",
            "mfa", "rmfa", "cfld", "cons", "ccigs", "cdel", "migs",
            "ifld", "sids", "icigs"
        ]

        for name in unsecured:
            src = getattr(self, name, None)
            dst = getattr(copy, name, None)
            if src is None or dst is None:
                continue
            for keys, val in src.getTopItemIter():
                dst.put(keys=keys, val=val)

        # -------------------------------------------------------------
        # 4. Copy set-based subdbs
        # -------------------------------------------------------------
        sets = ["esigs", "ecigs", "epath", "chas", "reps", "wkas", "meids", "maids"]

        for name in sets:
            src = getattr(self, name, None)
            dst = getattr(copy, name, None)
            if src is None or dst is None:
                continue
            for keys, val in src.getTopItemIter():
                dst.add(keys=keys, val=val)

        # -------------------------------------------------------------
        # 5. Copy imgs and iimgs
        # -------------------------------------------------------------
        for keys, val in self.imgs.getTopItemIter():
            copy.imgs.pin(keys=keys, val=val)

        for keys, val in self.iimgs.getTopItemIter():
            copy.iimgs.pin(keys=keys, val=val)

        # -------------------------------------------------------------
        # 6. Clone .habs and .names and prefix/group sets
        # -------------------------------------------------------------
        for keys, val in self.habs.getTopItemIter():
            if val.hid in copy.kevers:  # only copy verified habitats
                copy.habs.put(keys=keys, val=val)
                ns = "" if val.domain is None else val.domain
                copy.names.put(keys=(ns, val.name), val=val.hid)
                copy.prefixes.add(val.hid)
                if val.mid:
                    copy.groups.add(val.hid)

        # -------------------------------------------------------------
        # 7. Clone .ends and .locs
        # -------------------------------------------------------------
        for (cid, role, eid), val in self.ends.getTopItemIter():
            exists = False
            for scheme in ("https", "http", "tcp"):
                lval = self.locs.get(keys=(eid, scheme))
                if lval:
                    exists = True
                    copy.locs.put(keys=(eid, scheme), val=lval)
            if exists:
                copy.ends.put(keys=(cid, role, eid), val=val)

        # -------------------------------------------------------------
        # 8. Replace kevers, prefixes, groups in self with cloned ones
        # -------------------------------------------------------------
        self.kevers.clear()
        for pre, kever in copy.kevers.items():
            self.kevers[pre] = kever

        self.prefixes.clear()
        self.prefixes.update(copy.prefixes)

        self.groups.clear()
        self.groups.update(copy.groups)

        # -------------------------------------------------------------
        # 9. Replace old IndexedDB database with the clean clone
        # -------------------------------------------------------------
        await self._replaceIndexedDB(copy)

        # -------------------------------------------------------------
        # 10. Reopen this WebBaser using the new DB
        # -------------------------------------------------------------
        await self.reopen()


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

        for keys, fn, dig in self.fels.getAllItemIter(keys=pre, on=fn):
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
        for keys, fn, dig in self.fels.getAllItemIter(keys=b'', on=0):
            pre = keys[0].encode() if isinstance(keys[0], str) else keys[0]
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
        from ..core import coring
        from ..core.counting import Counter, Codens

        msg = bytearray()  # message
        atc = bytearray()  # attachments
        dgkey = dgKey(pre, dig)  # get message
        if not (serder := self.evts.get(keys=(pre, dig))):
            raise MissingEntryError("Missing event for dig={}.".format(dig))
        msg.extend(serder.raw)

        # add indexed signatures to attachments
        if not (sigers := self.sigs.get(keys=dgkey)):
            raise MissingEntryError("Missing sigs for dig={}.".format(dig))
        atc.extend(Counter(code=Codens.ControllerIdxSigs,
                           count=len(sigers), version=Vrsn_1_0).qb64b)
        for siger in sigers:
            atc.extend(siger.qb64b)

        # add indexed witness signatures to attachments
        if wigers := self.wigs.get(keys=dgkey):
            atc.extend(Counter(code=Codens.WitnessIdxSigs,
                               count=len(wigers), version=Vrsn_1_0).qb64b)
            for wiger in wigers:
                atc.extend(wiger.qb64b)

        # add authorizer (delegator/issuer) source seal event couple to attachments
        if (duple := self.aess.get(keys=(pre, dig))) is not None:
            number, diger = duple
            atc.extend(Counter(code=Codens.SealSourceCouples,
                               count=1, version=Vrsn_1_0).qb64b)
            atc.extend(number.qb64b + diger.qb64b)

        # add trans endorsement quadruples to attachments not controller
        # may have been originally key event attachments or receipted endorsements
        if quads := self.vrcs.get(keys=dgkey):
            atc.extend(Counter(code=Codens.TransReceiptQuadruples,
                               count=len(quads), version=Vrsn_1_0).qb64b)
            for pre, snu, diger, siger in quads:    # adapt to CESR
                atc.extend(pre.qb64b)
                atc.extend(snu.qb64b)
                atc.extend(diger.qb64b)
                atc.extend(siger.qb64b)

        # add nontrans endorsement couples to attachments not witnesses
        # may have been originally key event attachments or receipted endorsements
        if coups := self.rcts.get(keys=dgkey):
            atc.extend(Counter(code=Codens.NonTransReceiptCouples,
                               count=len(coups), version=Vrsn_1_0).qb64b)
            for prefixer, cigar in coups:
                atc.extend(prefixer.qb64b)
                atc.extend(cigar.qb64b)

        # add first seen replay couple to attachments
        if not (dater := self.dtss.get(keys=dgkey)):
            raise MissingEntryError("Missing datetime for dig={}.".format(dig))
        atc.extend(Counter(code=Codens.FirstSeenReplayCouples,
                           count=1, version=Vrsn_1_0).qb64b)
        atc.extend(coring.Number(num=fn, code=coring.NumDex.Huge).qb64b)  # may not need to be Huge
        atc.extend(dater.qb64b)

        # prepend pipelining counter to attachments
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        pcnt = Counter(code=Codens.AttachmentGroup,
                       count=(len(atc) // 4), version=Vrsn_1_0).qb64b
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
        from ..core.structing import SealEvent

        if tuple(seal) != SealEvent._fields:  # wrong type of seal
            return None

        seal = SealEvent(**seal)  #convert to namedtuple

        for srdr in self.getEvtPreIter(pre=pre, sn=sn):  # includes disputed & superseded
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == SealEvent._fields:
                    eseal = SealEvent(**eseal)  # convert to namedtuple
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
        from ..core.structing import SealEvent

        if tuple(seal) != SealEvent._fields:  # wrong type of seal
            return None

        seal = SealEvent(**seal)  #convert to namedtuple

        for srdr in self.getEvtLastPreIter(pre=pre, sn=sn):  # no disputed or superseded
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == SealEvent._fields:
                    eseal = SealEvent(**eseal)  # convert to namedtuple
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

        for srdr in self.getEvtLastPreIter(pre=pre, sn=sn):  # only last evt at sn
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
        # get unique verified wigers and windices lists from wigers list
        wigers = self.wigs.get(keys=(serder.preb, serder.saidb))
        kever = self.kevers[serder.pre]
        toad = kever.toader.num

        return not len(wigers) < toad

    def resolveVerifiers(self, pre=None, sn=0, dig=None):
        """
        Returns the Tholder and Verfers for the provided identifier prefix.
        Default pre is own .pre

        Parameters:
            pre(str) is qb64 str of bytes of identifier prefix.
            sn(int) is the sequence number of the est event
            dig(str) is qb64 str of digest of est event

        """
        from ..core import coring

        prefixer = coring.Prefixer(qb64=pre)
        if prefixer.transferable:
            # receipted event and receipter in database so get receipter est evt
            # retrieve dig of last event at sn of est evt of receipter.
            sdig = self.kels.getLast(keys=prefixer.qb64b, on=sn)
            if sdig is None:
                # receipter's est event not yet in receipters's KEL
                raise ValidationError("key event sn {} for pre {} is not yet in KEL"
                                             "".format(sn, pre))
            sdig = sdig.encode("utf-8")
            # retrieve last event itself of receipter est evt from sdig
            sserder = self.evts.get(keys=(prefixer.qb64b, bytes(sdig)))
            # assumes db ensures that sserder must not be none because sdig was in KE
            if dig is not None and not sserder.compare(said=dig):  # endorser's dig not match event
                raise ValidationError("Bad proof sig group at sn = {}"
                                             " for ksn = {}."
                                             "".format(sn, sserder.sad))

            verfers = sserder.verfers
            tholder = sserder.tholder

        else:
            verfers = [coring.Verfer(qb64=pre)]
            tholder = coring.Tholder(sith="1")

        return tholder, verfers

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

        for dig in self.kels.getAllIter(keys=pre, on=sn):
            try:
                if not (serder := self.evts.get(keys=(pre, dig))):
                    raise MissingEntryError("Missing event for dig={}.".format(dig))

            except Exception:
                continue  # skip this event

            yield serder  # event as Serder


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

        for dig in self.kels.getLastIter(keys=pre, on=sn):
            try:

                if not (serder := self.evts.get(keys=(pre, dig) )):
                    raise MissingEntryError("Missing event for dig={}.".format(dig))

            except Exception:
                continue  # skip this event

            yield serder  # event as Serder
