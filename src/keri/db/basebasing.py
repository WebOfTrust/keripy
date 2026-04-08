import importlib
import os
from collections import namedtuple
import semver
from ordered_set import OrderedSet as oset

from hio.help import ogler

from keri import __version__
from ..kering import (MissingEntryError, DatabaseError,
                      ConfigurationError, ValidationError,
                      Vrsn_1_0, Vrsn_2_0)

logger = ogler.getLogger()

# Repeated code from dbing
def dgKey(pre, dig):
    """
    Returns bytes DB key from concatenation of '.' with qualified Base64 prefix
    bytes pre and qualified Base64 bytes digest of serialized event
    If pre or dig are str then converts to bytes
    """
    if hasattr(pre, "encode"):
        pre = pre.encode("utf-8")  # convert str to bytes
    if hasattr(dig, "encode"):
        dig = dig.encode("utf-8")  # convert str to bytes
    return (b'%s.%s' %  (pre, dig))


class statedict(dict):
    """
    Subclass of dict that has db as attribute and employs read through cache
    from db Baser.stts of kever states to reload kever from state in database
    when not found in memory as dict item.
    """
    __slots__ = ('db')  # no .__dict__ just for db reference

    def __init__(self, *pa, **kwa):
        super(statedict, self).__init__(*pa, **kwa)
        self.db = None

    def __getitem__(self, k):
        try:
            return super(statedict, self).__getitem__(k)
        except KeyError as ex:
            if not self.db:
                raise ex  # reraise KeyError
            if (ksr := self.db.states.get(keys=k)) is None:
                raise ex  # reraise KeyError
            try:
                from ..core.eventing import Kever
                kever = Kever(state=ksr, db=self.db)
            except MissingEntryError:  # no kel event for keystate
                raise ex  # reraise KeyError
            self.__setitem__(k, kever)
            return kever

    def __contains__(self, k):
        if not super(statedict, self).__contains__(k):
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
        if not super(statedict, self).__contains__(k):
            return default
        else:
            return self.__getitem__(k)

def _strip_prerelease(version_str):
    """Strip prerelease and build metadata from a semver string.

    Semver compares alphanumeric prerelease identifiers lexicographically,
    so 'dev4' > 'dev10' (because '4' > '1'). Stripping prerelease ensures
    dev releases within the same version cycle compare as equal.
    See: https://github.com/WebOfTrust/keripy/issues/820
    """
    ver = semver.VersionInfo.parse(version_str)
    return str(semver.Version(ver.major, ver.minor, ver.patch))


MIGRATIONS = [
    ("0.6.8", ["hab_data_rename"]),
    ("1.0.0", ["add_key_and_reg_state_schemas"]),
    ("1.2.0", ["rekey_habs"])
]

class BaserBase:
    """
    Base class for Baser and WebBaser.

    BaserBase provides minimal, non‑persistent structures like
    prefixes, groups, kevers and db as well as common functions. 

    Attributes:
        - prefixes (oset): set of local prefix identifiers (`prefixes`)
        - groups (oset): set of group identifiers (`groups`)
        - _kevers (statedict): in‑memory mapping of prefix to Kever
        - db: db where `_kevers.db` points back to this instance so that kever
          lookups and read‑through caching work correctly

    This class must be initialized *before* any LMDB‑backed components
    so that reload() has valid in‑memory targets to populate.
    """

    def __init__(self, **kwa):

        self.prefixes = oset()  # should change to hids for hab ids
        self.groups = oset()  # group hab ids
        self._kevers = statedict()
        self._kevers.db = self  # assign db for read through cache of kevers

    @property
    def kevers(self):
        """
        Returns .db.kevers
        """
        return self._kevers


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

