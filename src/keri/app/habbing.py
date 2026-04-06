# -*- encoding: utf-8 -*-
"""
KERI
keri.app.habbing module

"""
from contextlib import contextmanager
from math import ceil
from urllib.parse import urlsplit

from hio.base import doing
from hio.help import hicting, ogler

from .configing import Configer
from .keeping import Keeper, Manager

from ..peer import Exchanger, exchange
from ..db import Baser, dgKey, fetchTsgs
from ..help import fromIso8601, toIso8601
from ..kering import (Vrsn_1_0, Ilks, ClosedError, AuthError,
                ConfigurationError, ValidationError, MissingEntryError,
                KeriError, MissingSignatureError, Roles, Schemes)
from ..core import (Tholder, Diger, Prefixer, Kevery, Parser, Revery,
                    Router, Counter, Salter, SealEvent, SealLast,
                    Codens, MtrDex, TraitDex,
                    deltate, messagize, delcept,
                    rotate as rotateEvent,
                    incept as inceptEvent,
                    interact as interactEvent,
                    query as queryEvent,
                    receipt as receiptEvent,
                    reply as replyEvent)
from ..recording import HabitatRecord, OobiRecord


logger = ogler.getLogger()

@contextmanager
def openHby(*, name="test", base="", temp=True, salt=None, **kwa):
    """Context manager that creates and yields a ``Habery`` instance, closing
    and optionally clearing it on exit.

    Args:
        name (str): Name used for the shared databases and config file path.
        base (str): Optional path component inserted before ``name`` for
            further hierarchical differentiation of databases. Empty string
            means no additional component.
        temp (bool): When ``True``, stores ``.ks``, ``.db``, and ``.cf`` in
            ``/tmp`` and uses a fast (low-cost) salt-stretch method suitable
            for testing.  When ``False``, uses the resource tier specified by
            ``tier``.
        salt (str): qb64-encoded salt used for key-pair creation.  A fresh
            random salt is generated when ``None``.
        **kwa: Additional keyword arguments forwarded to ``Habery.__init__``.
            See ``Habery`` for the full list (``seed``, ``aeid``, ``bran``,
            ``pidx``, ``algo``, ``tier``, ``free``).

    Yields:
        Habery: Fully initialised ``Habery`` instance.
    """
    habery = None
    salt = salt if salt is not None else Salter().qb64
    try:
        habery = Habery(name=name, base=base, temp=temp, salt=salt, **kwa)
        yield habery

    finally:
        if habery:
            habery.close(clear=habery.temp)


@contextmanager
def openHab(name="test", base="", salt=None, temp=True, cf=None, **kwa):
    """Context manager that creates and yields a ``(Habery, Hab)`` pair,
    closing and optionally clearing resources on exit.

    If a ``Hab`` with ``name`` already exists in the ``Habery`` it is reused;
    otherwise a new single-key ``Hab`` (``icount=1, isith='1', ncount=1,
    nsith='1'``) is created via ``Habery.makeHab``.

    Args:
        name (str): Name of the ``Hab`` (and the underlying shared databases).
        base (str): Optional path component for shared resources.  See
            ``openHby``.
        salt (bytes | None): Raw (not qb64) salt bytes passed to ``Habery``.
            Converted to qb64 internally.  A fresh salt is generated when
            ``None``.
        temp (bool): ``True`` means use temporary databases.  See ``openHby``.
        cf (Configer | None): Optional ``Configer`` instance for loading
            configuration data.
        **kwa: Additional keyword arguments forwarded to ``Habery.makeHab``.

    Yields:
        tuple[Habery, Hab]: The shared ``Habery`` environment and the named
            ``Hab`` instance.
    """

    salt = Salter(raw=salt).qb64

    with openHby(name=name, base=base, salt=salt, temp=temp, cf=cf) as hby:
        if (hab := hby.habByName(name)) is None:
            hab = hby.makeHab(name=name, icount=1, isith='1', ncount=1, nsith='1', cf=cf, **kwa)

        yield hby, hab


class Habery:
    """Shared environment for a collection of ``Hab`` (Habitat) instances.

    Provides a single keystore (``Keeper``), event database (``Baser``), and
    config file (``Configer``) that are shared among all ``Hab`` instances
    created within this environment.  Also owns the ``Manager``, ``Router``,
    ``Revery``, ``Kevery``, and ``Parser`` used for key management and event
    processing.

    Attributes:
        name (str): Name used for the associated databases and config file.
        base (str): Optional directory path segment inserted before ``name``
            for hierarchical differentiation of databases.  Empty string means
            no additional component.
        temp (bool): ``True`` means temporary storage and fast (test-suitable)
            salt stretching.  ``False`` means persistent storage and
            tier-appropriate key stretching.
        ks (Keeper): LMDB keystore instance.
        db (Baser): LMDB event database instance for KELs etc.
        cf (Configer): Config file instance.
        mgr (Manager or None): Key manager for creating and rotating keys.
            ``None`` until ``setup`` completes successfully.
        rtr (Router): Routes ``rpy`` (reply) messages to registered handlers.
        rvy (Revery): Processes ``rpy`` messages.
        exc (Exchanger): Processes ``exn`` (exchange) messages.
        kvy (Kevery): Processes local key-event messages.
        psr (Parser): Parses framed local messages, dispatching to ``kvy``,
            ``rvy``, and ``exc``.
        habs (dict): ``Hab`` instances keyed by their qb64 prefix.
            Use ``habByName`` to look up by name and ``habByPre`` to look up
            by prefix.
        inited (bool): ``True`` once ``setup`` has completed successfully.
    """

    def __init__(self, *, name='test', base="", temp=False,
                 ks=None, db=None, cf=None, clear=False, headDirPath=None, **kwa):
        """Initialise a ``Habery`` instance.

        Opens (or reuses) the keystore, event database, and config file, then
        calls ``setup`` if both ``db`` and ``ks`` are already open.  When
        dependency-injected stores are not yet open (e.g. in an async context),
        ``setup`` must be called explicitly once they have been opened.

        Args:
            name (str): Alias name for the shared environment, databases, and
                config file.
            base (str): Optional directory path segment inserted before
                ``name``.  Empty string means no additional component.
            temp (bool): ``True`` means use temporary storage in ``/tmp`` and
                fast salt-stretch methods suitable for testing.
            ks (Keeper | None): Existing open keystore to reuse.  A new
                ``Keeper`` is created when ``None``.
            db (Baser | None): Existing open event database to reuse.  A new
                ``Baser`` is created when ``None``.
            cf (Configer | None): Existing config file instance to reuse.  A
                new ``Configer`` is created when ``None``.
            clear (bool): When ``True``, removes the resource directory on
                ``close``.
            headDirPath (str | None): Override for the top-level directory path
                used when creating ``ks`` and ``db``.
            **kwa: Keyword arguments forwarded to ``setup`` and stored in
                ``_inits`` for deferred initialisation.  See ``setup`` for the
                full parameter list (``seed``, ``aeid``, ``bran``, ``pidx``,
                ``algo``, ``salt``, ``tier``, ``free``).
        """
        self.name = name
        self.base = base
        self.temp = temp

        self.ks = ks if ks is not None else Keeper(name=self.name,
                                                           base=self.base,
                                                           temp=self.temp,
                                                           reopen=True,
                                                           clear=clear,
                                                           headDirPath=headDirPath)
        self.db = db if db is not None else Baser(name=self.name,
                                                  base=self.base,
                                                  temp=self.temp,
                                                  reopen=True,
                                                  clear=clear,
                                                  headDirPath=headDirPath)
        self.cf = cf if cf is not None else Configer(name=self.name,
                                                               base=self.base,
                                                               temp=self.temp,
                                                               reopen=True,
                                                               clear=clear)

        self.mgr = None  # wait to setup until after ks is known to be opened
        self.rtr = Router()
        self.rvy = Revery(db=self.db, rtr=self.rtr)
        self.exc = Exchanger(hby=self, handlers=[])
        self.kvy = Kevery(db=self.db, lax=False, local=True, rvy=self.rvy)
        self.kvy.registerReplyRoutes(router=self.rtr)
        self.psr = Parser(framed=True, kvy=self.kvy, rvy=self.rvy,
                                  exc=self.exc, local=True, version=Vrsn_1_0)
        self.habs = {}  # empty .habs
        self._signator = None
        self.inited = False

        # save init kwy word arg parameters as ._inits in order to later finish
        # init setup elseqhere after databases are opened if not below
        self._inits = kwa
        self._inits['temp'] = temp  # add temp for seed from bran tier override

        if self.db.opened and self.ks.opened:
            self.setup(**self._inits)  # finish setup later


    def setup(self, *, seed=None, aeid=None, bran=None, pidx=None, algo=None,
              salt=None, tier=None, free=False, temp=None, ):
        """Finish initialisation of the ``Habery`` after ``db`` and ``ks`` are open.

        Intended to be called once both ``.db`` and ``.ks`` have been opened.
        This separation allows dependency injection of database instances that
        may be opened asynchronously after ``__init__``.  The first successful
        call performs vacuous (initial) database setup.

        Args:
            seed (str | None): qb64 private signing key (seed) for the
                ``aeid``.  Used to derive the private decryption key and to
                authenticate the ``Manager``.  This value is **memory-only**
                and must never be persisted to the database.  It must be loaded
                exactly once when the process starts and stored on a separate
                device from the one running the ``Manager``.
            aeid (str | None): qb64 non-transferable identifier prefix used for
                authentication and encryption of secrets in the keystore.  When
                provided and different from the ``aeid`` already in the
                database, all secrets are re-encrypted under the new ``aeid``;
                in this case ``seed`` must also be provided.  An ``aeid``
                change should require a second authentication factor in
                addition to ``seed``.
            bran (str | None): Base64 string of at least 21 characters used as
                base material to derive ``seed`` via salt stretching.  Allows
                alphanumeric passcodes (e.g. from a password manager) to serve
                as the key-store secret.  Ignored when ``seed`` is provided.
            pidx (int | None): Initial prefix index for a vacuous (empty)
                keystore.
            algo (str | None): Key-pair generation algorithm (``'randy'`` or
                ``'salty'``).  Defaults to the root algorithm (salty) when
                ``None``.
            salt (str | None): qb64 salt used for signing-key creation.  A
                fresh random salt is generated when ``None``.
            tier (str | None): Security tier (``Tierage``) controlling the
                cost of salt-to-seed stretching.
            free (bool): When ``True``, releases (closes) resources when the
                associated ``Doer`` exits.
            temp (bool | None): When ``True``, overrides the instance
                ``temp`` flag to use fast salt-stretch methods during setup.

        Raises:
            ClosedError: If ``.ks`` or ``.db`` is not open when called.
            ValueError: If ``bran`` is shorter than 21 characters.
            AuthError: If the provided ``seed`` does not authenticate the
                ``aeid`` stored in the keystore.
        """
        if not (self.ks.opened and self.db.opened):
            raise ClosedError("Attempt to setup Habitat with closed "
                                     "database, .ks or .db.")
        self.free = True if free else False

        if bran and not seed:  # create seed from stretch of bran as salt
            if len(bran) < 21:
                raise ValueError(f"Bran (passcode seed material) too short.")
            bran = MtrDex.Salt_128 + 'A' + bran[:21]  # qb64 salt for seed
            signer = Salter(qb64=bran).signer(transferable=False,
                                                     tier=tier,
                                                     temp=temp)
            seed = signer.qb64
            if not aeid:  # aeid must not be empty event on initial creation
                aeid = signer.verfer.qb64  # lest it remove encryption

        if salt is None:  # salt for signing keys not aeid seed
            salt = Salter().qb64
        else:
            salt = Salter(qb64=salt).qb64

        try:
            self.mgr = Manager(ks=self.ks, seed=seed, aeid=aeid, pidx=pidx,
                                       algo=algo, salt=salt, tier=tier)
        except AuthError as ex:
            self.close()
            raise ex

        self._signator = Signator(db=self.db, mgr=self.mgr, temp=self.temp, ks=self.ks, cf=self.cf,
                                  rtr=self.rtr, kvy=self.kvy, psr=self.psr, rvy=self.rvy)

        self.loadHabs()
        self.inited = True

    def loadHabs(self):
        """Load all ``Hab`` instances persisted in the database into ``.habs``.

        Called by ``setup`` after the keystore and event database are open and
        ``db.reload`` has already populated ``db.kevers`` and ``db.prefixes``
        from stored key state, removing any orphaned hab records without valid
        key state.

        Each record in ``db.habs`` is inspected to determine the correct ``Hab``
        subclass:

        * ``GroupHab`` — ``mid`` set, ``sid`` not set (local multisig group).
        * ``SignifyHab`` — ``sid`` set, ``mid`` not set (Signify-managed
          single identifier).
        * ``SignifyGroupHab`` — both ``sid`` and ``mid`` set (Signify-managed
          multisig group).
        * ``Hab`` — neither ``sid`` nor ``mid`` set (standard local
          identifier).

        After all habs are loaded, group habs have their ``.mhab`` (local
        member hab) populated from ``.habs``.  ``reconfigure`` is called both
        before and after loading.

        Raises:
            ConfigurationError: If a non-group ``Hab`` loaded from the database
                has not been accepted into its own local KEL.
        """
        self.reconfigure()  # pre hab load reconfiguration

        groups = []
        for prefix, habord in self.db.habs.getTopItemIter():
            pre = habord.hid

            # create Hab instance and inject dependencies
            if habord.mid and not habord.sid:
                hab = GroupHab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                               rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                               name=habord.name, pre=pre, temp=self.temp, smids=habord.smids)
                groups.append(habord)
            elif habord.sid and not habord.mid:
                hab = SignifyHab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                                 rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                                 name=habord.name, pre=habord.sid)
            elif habord.sid and habord.mid:
                hab = SignifyGroupHab(smids=habord.smids, ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                                      rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                                      name=habord.name, pre=pre)
                groups.append(habord)
            else:
                hab = Hab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                          rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                          name=habord.name, pre=pre, temp=self.temp)

            # Rules for acceptance:
            # It is accepted into its own local KEL even if it has not been fully
            # witnessed and if delegated, its delegator has not yet sealed it
            if not hab.accepted and not habord.mid:
                raise ConfigurationError(f"Problem loading Hab pre="
                                                f"{pre} name={habord.name} from db.")

            # read in config file and process any oobis or endpoints for hab
            hab.inited = True
            self.habs[hab.pre] = hab

        # Populate the participant hab after loading all habs
        for habord in groups:
            self.habs[habord.hid].mhab = self.habs[habord.mid]

        self.reconfigure()  # post hab load reconfiguration

    def makeHab(self, name, ns=None, cf=None, **kwa):
        """Create, persist, and return a new local ``Hab``.

        The new ``Hab`` is registered in ``.habs`` keyed by its generated
        prefix.

        Args:
            name (str): Human-readable alias for the new identifier.
            ns (str | None): Optional namespace for the identifier.  Must not
                contain a ``'.'`` character.
            cf (Configer | None): Config file instance to use for this hab.
                Defaults to ``self.cf`` when ``None``.
            **kwa: Keyword arguments forwarded to ``Hab.make``:

                * ``secrecies`` (list): Pre-loaded key-pair secrets.
                * ``iridx`` (int): Initial rotation index after secret ingestion.
                * ``code`` (str): Prefix derivation code.
                * ``transferable`` (bool): ``True`` (default) for a
                  transferable prefix; ``False`` for non-transferable.
                * ``isith`` (int | str | list): Inception signing threshold.
                * ``icount`` (int): Number of inception signing keys.
                * ``nsith`` (int | str | list): Next signing threshold.
                * ``ncount`` (int): Number of next (pre-rotated) keys.
                * ``toad`` (int | str): Witness threshold.
                * ``wits`` (list[str]): qb64 witness prefixes.
                * ``delpre`` (str): qb64 delegator prefix.
                * ``estOnly`` (str): ``TraitDex.EstOnly`` to restrict the KEL
                  to establishment events only.
                * ``data`` (list | None): Seal dicts for the inception event.

        Returns:
            Hab: The newly created and persisted ``Hab`` instance.

        Raises:
            ConfigurationError: If ``ns`` contains a ``'.'`` character.
        """
        if ns is not None and "." in ns:
            raise ConfigurationError("Hab namespace names are not allowed to contain the '.' character")

        cf = cf if cf is not None else self.cf
        hab = Hab(ks=self.ks, db=self.db, cf=cf, mgr=self.mgr,
                  rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                  name=name, ns=ns, temp=self.temp)

        hab.make(**kwa)

        self.habs[hab.pre] = hab
        return hab

    def makeGroupHab(self, group, mhab, smids, rmids=None, ns=None, **kwa):
        """Create, persist, and return a new multisig ``GroupHab``.

        The KEL for each signing and rotation member must already be present in
        ``.kevers`` before calling this method.  Current signing keys are
        extracted from each member's latest establishment event to form the
        group's inception keys (``merfers``), and next key digests form the
        group's next key commitments (``migers``).

        Args:
            group (str): Human-readable alias for the group identifier.
            mhab (Hab): The local participant ``Hab`` that is a member of this
                group.
            smids (list[str]): qb64 prefixes of the signing members.  Each
                must have a KEL in ``.kevers`` and exactly one current signing
                key.
            rmids (list[str] | None): qb64 prefixes of the rotation members
                from which next key digests are extracted.  When ``None``,
                ``smids`` is used for both signing and rotation.  An empty list
                produces a group identifier with no next key commitments
                (non-transferable after inception).
            ns (str | None): Optional namespace for the group identifier.
            **kwa: Keyword arguments forwarded to ``GroupHab.make``.  See
                ``makeHab`` for the full list; additionally:

                * ``DnD`` (bool): ``TraitDex.DnD`` to disallow delegated
                  identifiers from this identifier.

        Returns:
            GroupHab: The newly created and persisted ``GroupHab`` instance.

        Raises:
            ConfigurationError: If ``mhab.pre`` is not present in either
                ``smids`` or ``rmids``, if a signing member's KEL is missing
                from ``.kevers``, if a rotation member's KEL is missing from
                ``.kevers``, or if any member has more than one current signing
                key or more than one next key digest.
        """

        if mhab.pre not in smids and mhab.pre not in rmids:
            raise ConfigurationError(f"Local member identifier "
                                            f"{mhab.pre} must be member of "
                                            f"smids ={smids} and/or "
                                            f"rmids={rmids}.")

        for mid in smids:
            if mid not in self.kevers:
                raise ConfigurationError(f"KEL missing for signing member "
                                                f"identifier {mid} from group's "
                                                f"current members ={smids}")

        if rmids is not None:
            for rmid in rmids:
                if rmid not in self.kevers:
                    raise ConfigurationError(f"KEL missing for next member "
                                                    f"identifier {rmid} in group's"
                                                    f" next members ={rmids}")

        # multisig group verfers of current signing keys and digers of next key digests
        merfers, migers = self.extractMerfersMigers(smids, rmids)  # group verfers and digers
        kwa["merfers"] = merfers
        kwa["migers"] = migers

        # create group Hab in this Habery
        hab = GroupHab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                       rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                       name=group, ns=ns, mhab=mhab, smids=smids, rmids=rmids, temp=self.temp)

        hab.make(**kwa)  # finish making group hab with injected pass throughs
        self.habs[hab.pre] = hab
        return hab

    def joinGroupHab(self, pre, group, mhab, smids, rmids=None, ns=None):
        """Join an existing multisig group as a participant without creating a
        new inception event.

        Used when the group's inception event was initiated by another
        participant and this node is joining after the fact.  The group
        ``Hab`` is constructed, its prefix set to ``pre``, and the record
        persisted directly rather than through ``Hab.make``.

        Args:
            pre (str): qb64 prefix of the already-established group identifier.
            group (str): Human-readable alias for the group identifier.
            mhab (Hab): The local participant ``Hab`` that is a member of this
                group.
            smids (list[str]): qb64 prefixes of the signing members.
            rmids (list[str] | None): qb64 prefixes of the rotation members.
                When ``None``, ``smids`` is used for both.  An empty list means
                the group is non-transferable after inception.
            ns (str | None): Optional namespace for the group identifier.

        Returns:
            GroupHab: The newly created and persisted ``GroupHab`` instance
                with ``.pre`` set to ``pre``.

        Raises:
            ConfigurationError: If ``mhab.pre`` is not in ``smids`` or
                ``rmids``, or if a member's KEL is missing from ``.kevers``.
        """

        if mhab.pre not in smids and mhab.pre not in rmids:
            raise ConfigurationError(f"Local member identifier "
                                            f"{mhab.pre} must be member of "
                                            f"smids ={smids} and/or "
                                            f"rmids={rmids}.")

        for mid in smids:
            if mid not in self.kevers:
                raise ConfigurationError(f"KEL missing for signing member "
                                                f"identifier {mid} from group's "
                                                f"current members ={smids}")

        if rmids is not None:
            for rmid in rmids:
                if rmid not in self.kevers:
                    raise ConfigurationError(f"KEL missing for next member "
                                                    f"identifier {rmid} in group's"
                                                    f" next members ={rmids}")

        # create group Hab in this Habery
        hab = GroupHab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                       rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                       name=group, ns=ns, mhab=mhab, smids=smids, rmids=rmids, temp=self.temp)

        hab.pre = pre
        habord = HabitatRecord(hid=hab.pre,
                                      name=hab.name,
                                      domain=ns,
                                      mid=mhab.pre,
                                      smids=smids,
                                      rmids=rmids)

        hab.save(habord)
        hab.prefixes.add(pre)
        hab.inited = True

        self.habs[hab.pre] = hab
        return hab

    def makeSignifyHab(self, name, ns=None, **kwa):
        """Create, persist, and return a new ``SignifyHab`` (Signify-managed
        single identifier).

        Args:
            name (str): Human-readable alias for the identifier.
            ns (str | None): Optional namespace for the identifier.
            **kwa: Keyword arguments forwarded to ``SignifyHab.make``.

        Returns:
            SignifyHab: The newly created and persisted ``SignifyHab`` instance.
        """
        # create group Hab in this Habery
        hab = SignifyHab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                         rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                         name=name, ns=ns, temp=self.temp)

        hab.make(**kwa)  # finish making group hab with injected pass throughs
        self.habs[hab.pre] = hab
        return hab

    def makeSignifyGroupHab(self, name, mhab, smids, rmids=None,  ns=None, **kwa):
        """Create, persist, and return a new ``SignifyGroupHab`` (Signify-managed
        multisig group identifier).

        Args:
            name (str): Human-readable alias for the group identifier.
            mhab (Hab): The local participant ``Hab`` that is a member of this
                group.
            smids (list[str]): qb64 prefixes of the signing members.
            rmids (list[str] | None): qb64 prefixes of the rotation members.
                When ``None``, ``smids`` is used for both.
            ns (str | None): Optional namespace for the group identifier.
            **kwa: Keyword arguments forwarded to ``SignifyGroupHab.make``.

        Returns:
            SignifyGroupHab: The newly created and persisted
                ``SignifyGroupHab`` instance.
        """
        # create group Hab in this Habery
        hab = SignifyGroupHab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                              rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                              name=name, mhab=mhab, smids=smids, rmids=rmids, ns=ns, temp=self.temp)

        hab.make(**kwa)  # finish making group hab with injected pass throughs

        self.habs[hab.pre] = hab
        return hab

    def joinSignifyGroupHab(self, pre, name, mhab, smids, rmids=None, ns=None):
        """Join an existing Signify-managed multisig group as a participant
        without creating a new inception event.

        Analogous to ``joinGroupHab`` but for ``SignifyGroupHab`` instances.
        The group ``Hab`` is constructed with the given ``pre``, and the
        record is persisted directly.

        Args:
            pre (str): qb64 prefix of the already-established group identifier.
            name (str): Human-readable alias for the group identifier.
            mhab (Hab): The local participant ``Hab`` that is a member of this
                group.
            smids (list[str]): qb64 prefixes of the signing members.
            rmids (list[str] | None): qb64 prefixes of the rotation members.
                When ``None``, ``smids`` is used for both.  An empty list means
                the group is non-transferable after inception.
            ns (str | None): Optional namespace for the group identifier.

        Returns:
            SignifyGroupHab: The newly created and persisted
                ``SignifyGroupHab`` instance with ``.pre`` set to ``pre``.

        Raises:
            ConfigurationError: If ``mhab.pre`` is not in ``smids`` or
                ``rmids``, or if a member's KEL is missing from ``.kevers``.
        """

        if mhab.pre not in smids and mhab.pre not in rmids:
            raise ConfigurationError(f"Local member identifier "
                                            f"{mhab.pre} must be member of "
                                            f"smids ={smids} and/or "
                                            f"rmids={rmids}.")

        for mid in smids:
            if mid not in self.kevers:
                raise ConfigurationError(f"KEL missing for signing member "
                                                f"identifier {mid} from group's "
                                                f"current members ={smids}")

        if rmids is not None:
            for rmid in rmids:
                if rmid not in self.kevers:
                    raise ConfigurationError(f"KEL missing for next member "
                                                    f"identifier {rmid} in group's"
                                                    f" next members ={rmids}")

        # create group Hab in this Habery
        hab = SignifyGroupHab(ks=self.ks, db=self.db, cf=self.cf, mgr=self.mgr,
                              rtr=self.rtr, rvy=self.rvy, kvy=self.kvy, psr=self.psr,
                              name=name, mhab=mhab, smids=smids, rmids=rmids, ns=ns, temp=self.temp)

        hab.pre = pre
        habord = HabitatRecord(hid=hab.pre,
                                      sid=mhab.pre,
                                      name=name,
                                      domain=ns,
                                      smids=smids,
                                      rmids=rmids)

        hab.save(habord)
        hab.prefixes.add(pre)
        hab.inited = True

        self.habs[hab.pre] = hab
        return hab

    def deleteHab(self, name, ns=None):
        """Remove a ``Hab`` from the database and from ``.habs``.

        Also removes the name-to-prefix mapping, the prefix from
        ``db.prefixes``, and (if present) the entry from ``db.groups``.

        Args:
            name (str): Human-readable alias of the ``Hab`` to delete.
            ns (str | None): Namespace of the ``Hab``.  Defaults to ``""``
                when ``None``.

        Returns:
            bool: ``True`` if the ``Hab`` was found and successfully removed;
                ``False`` if it was not found or if either database removal
                failed.
        """
        hab = self.habByName(name, ns=ns)
        if not hab:
            return False

        if not self.db.habs.rem(keys=(hab.pre,)):
            return False

        ns = "" if ns is None else ns
        if not self.db.names.rem(keys=(ns, name)):
            return False

        del self.habs[hab.pre]
        self.db.prefixes.remove(hab.pre)
        if hab.pre in self.db.groups:
            self.db.groups.remove(hab.pre)

        return True

    def extractMerfersMigers(self, smids, rmids=None):
        """Extract group signing key verfers and next-key-digest digers from
        member KELs.

        For each signing member in ``smids``, the first (and only permitted)
        current signing key verfer is appended to ``merfers``.  For each
        rotation member in ``rmids``, the first (and only permitted) next key
        digest diger is appended to ``migers`` (members that have abandoned
        their identifier and have empty next digers are skipped).

        Args:
            smids (list[str]): qb64 prefixes of the signing members of the
                multisig group.  Each must have exactly one current signing key
                in ``.kevers``.
            rmids (list[str] | None): qb64 prefixes of the rotation members.
                When ``None``, ``smids`` is used for both signing and rotation.
                Each present member must have at most one next key digest in
                ``.kevers``.

        Returns:
            tuple[list[Verfer], list[Diger]]: A 2-tuple of
                ``(merfers, migers)`` where ``merfers`` is the ordered list of
                current signing key verfers and ``migers`` is the ordered list
                of next key digest digers for the group.

        Raises:
            ConfigurationError: If any signing member has more than one current
                signing key, or if any rotation member has more than one next
                key digest.
        """
        if rmids is None:  # default the same for both lists
            rmids = list(smids)

        merfers = []  # multisig group signing key verfers
        migers = []  # multisig group next key digest digers

        for mid in smids:
            kever = self.kevers[mid]
            verfers = kever.verfers
            merfers.append(verfers[0])  # assumes always verfers
            if len(verfers) > 1:
                raise ConfigurationError("Identifier must have only one key, {} has {}"
                                                .format(mid, len(verfers)))

        for mid in rmids:
            kever = self.kevers[mid]
            digers = kever.ndigers
            if digers:  # abandoned id  may have empty next digers
                migers.append(digers[0])
            if len(digers) > 1:
                raise ConfigurationError("Identifier must have only one next key commitment, {} has {}"
                                                .format(mid, len(digers)))

        return merfers, migers

    def close(self, clear=False):
        """Close all managed resources (keystore, database, config file).

        Args:
            clear (bool): When ``True``, remove the resource directories in
                addition to closing them.  Temporary resources (``temp=True``)
                are always cleared regardless of this flag.
        """
        if self.ks:
            self.ks.close(clear=self.ks.temp or clear)

        if self.db:
            self.db.close(clear=self.db.temp or clear)

        if self.cf:
            self.cf.close(clear=self.cf.temp)

    @property
    def kevers(self):
        """dict: All ``Kever`` instances from ``db.kevers``, keyed by qb64 prefix."""
        return self.db.kevers

    @property
    def prefixes(self):
        """OrderedSet: Local prefixes registered in ``db.prefixes``."""
        return self.db.prefixes

    def habByPre(self, pre):
        """Return the ``Hab`` instance for a given prefix, or ``None``.

        Args:
            pre (str): qb64 AID prefix to look up.

        Returns:
            Hab | None: The ``Hab`` registered under ``pre``, or ``None`` if
                not found.
        """
        if pre in self.habs:
            return self.habs[pre]

        return None

    def habByName(self, name, ns=None):
        """Return the ``Hab`` instance for a given name and optional namespace,
        or ``None``.

        Resolves the name to a prefix via ``db.names`` and then looks up the
        ``Hab`` in ``.habs``.

        Args:
            name (str): Human-readable alias of the ``Hab``.
            ns (str | None): Namespace of the ``Hab``.  Defaults to ``""``
                when ``None``.

        Returns:
            Hab | None: The matching ``Hab`` instance, or ``None`` if not
                found.
        """
        ns = "" if ns is None else ns
        if (pre := self.db.names.get(keys=(ns, name))) is not None:
            if pre in self.habs:
                return self.habs[pre]

        return None

    def reconfigure(self):
        """Apply configuration from the ``Configer`` config file to this
        ``Habery``.

        Reads the config file via ``self.cf.get()`` and processes any OOBI
        URLs found in the following keys, storing ``OobiRecord`` entries in
        the database:

        * ``iurls`` — introduction OOBI URLs written to ``db.oobis``.
        * ``durls`` — delegation OOBI URLs written to ``db.oobis``.
        * ``wurls`` — well-known (MFA) OOBI URLs written to ``db.woobi``.

        The config file is treated as read-only at initialisation time.
        Runtime state changes must be written to the database, not the config
        file.  The config file is intended to pre-load the database, not to
        act as a live database.

        Example config file (JSON or HJSON):

        .. code-block:: json

            {
                "dt": "2021-01-01T00:00:00.000000+00:00",
                "nel": {
                    "dt": "2021-01-01T00:00:00.000000+00:00",
                    "curls": ["tcp://localhost:5621/"]
                },
                "iurls": [
                    "tcp://localhost:5620/?role=peer&name=tam"
                ],
                "durls": [
                    "http://127.0.0.1:7723/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
                    "http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi"
                ],
                "wurls": [
                    "http://127.0.0.1:5644/.well-known/keri/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy?name=Root"
                ]
            }
        """
        conf = self.cf.get()
        if "dt" in conf:  # datetime of config file
            dt = fromIso8601(conf["dt"])  # raises error if not convert
            if "iurls" in conf:  # process OOBI URLs
                for oobi in conf["iurls"]:
                    obr = OobiRecord(date=toIso8601(dt))
                    self.db.oobis.put(keys=(oobi,), val=obr)
            if "durls" in conf:  # process OOBI URLs
                for oobi in conf["durls"]:
                    obr = OobiRecord(date=toIso8601(dt))
                    self.db.oobis.put(keys=(oobi,), val=obr)
            if "wurls" in conf:  # well known OOBI URLs for MFA
                for oobi in conf["wurls"]:
                    obr = OobiRecord(date=toIso8601(dt))
                    self.db.woobi.put(keys=(oobi,), val=obr)

    @property
    def signator(self):
        """Signator: Signer and verifier for data-at-rest in this ``Habery``
        environment.  ``None`` until ``setup`` completes successfully.
        """
        return self._signator


SIGNER = "__signatory__"


class Signator:
    """Manages a non-transferable identifier used to sign and verify data at rest.

    Creates a single non-transferable AID on first initialization and persists it
    in the Habery database. Subsequent instantiations with the same name rehydrate
    the existing AID. Intended for signing BADA data to ensure integrity at rest.

    Attributes:
        db (Baser): Database environment used for key state and prefix storage.
        pre (str): Qualified Base64 AID prefix for the signing identifier.
    """

    def __init__(self, db, name=SIGNER, **kwa):
        """Initializes the Signator, creating a new signing AID if none exists for name.

        Looks up name in the Habery prefix index. If absent, creates a new
        non-transferable, hidden Hab and pins its prefix. If present, rehydrates
        the existing Hab from the stored prefix.

        Args:
            db (Baser): Database environment for key state and AID storage.
            name (str): Label used to look up or register the signing AID.
                Defaults to SIGNER.
            **kwa: Additional keyword arguments forwarded to Hab.
        """
        self.db = db
        spre = self.db.hbys.get(name)
        if not spre:
            self._hab = Hab(name=name, db=db, **kwa)
            self._hab.make(transferable=False, hidden=True)
            self.pre = self._hab.pre
            self.db.hbys.pin(name, self.pre)
        else:
            self.pre = spre
            self._hab = Hab(name=name, db=db, pre=self.pre, **kwa)

    def sign(self, ser):
        """Signs raw bytes using the Signator's non-transferable private key.

        Delegates to the underlying Hab's sign method with indexed=False,
        returning the first (and only) Cigar signature object.

        Args:
            ser (bytes): Raw byte data to sign.

        Returns:
            Cigar: Non-indexed signature over ser using the current verfer's
                private key.
        """
        return self._hab.sign(ser, indexed=False)[0]

    def verify(self, ser, cigar):
        """Verifies a Cigar signature against raw bytes using the current verfer.

        Checks the raw signature in cigar against ser using the first verfer
        on the Signator's current key event state (kever).

        Args:
            ser (bytes): Raw byte data to verify against the signature.
            cigar (Cigar): Non-transferable signature to verify.

        Returns:
            bool: True if the signature is cryptographically valid for ser,
                False otherwise.
        """
        return self._hab.kever.verfers[0].verify(cigar.raw, ser)


class HaberyDoer(doing.Doer):
    """Doer subclass that manages Habery lifecycle within a coroutine context.

    Initializes the Habery on enter if not already inited, and closes it on
    exit if inited and free. Intended to drive Habery setup and teardown as
    part of a Doist-managed task graph.

    Attributes:
        habery (Habery): Habery instance whose lifecycle this doer manages.

    Inherited Attributes:
        done (bool): Completion state. ``True`` means finished normally;
            ``False`` indicates incomplete due to close or abort.
        tyme (float): Relative cycle time obtained from the injected
            ``tymth`` closure.
        tymth (callable): Injected closure returned by ``Tymist.tymeth()``.
            Call it to get the current ``Tymist.tyme``. Injected via
            ``wind()``.
        tock (float): Desired seconds between ``recur`` calls. Zero means run
            ASAP. Non-negative.

    Note:
        Implements the Doer coroutine protocol: ``enter``, ``recur``,
        ``exit``, ``close``, and ``abort``. See ``doing.Doer`` for the full
        interface.
    """
    def __init__(self, habery, **kwa):
        """Initializes HaberyDoer with the Habery instance to manage.

        Args:
            habery (Habery): Habery instance to initialize and close during
                the doer lifecycle.
            **kwa: Additional keyword arguments forwarded to Doer.__init__.
        """
        super(HaberyDoer, self).__init__(**kwa)
        self.habery = habery

    def enter(self, *, temp=None):
        """Enters the doer context and initializes Habery if not already inited.

        Calls habery.setup() with its stored _inits parameters only when
        habery.inited is False. No-ops if Habery is already initialized.

        Args:
            temp (bool | None): Unused in this implementation. Present for
                interface compatibility with the base Doer enter signature.
        """
        if not self.habery.inited:
            self.habery.setup(**self.habery._inits)

    def exit(self):
        """Exits the doer context and closes Habery if inited and free.

        Calls habery.close() with clear set to habery.temp, which causes
        database files to be removed when operating in temporary mode.
        No-ops if Habery is not inited or not free.
        """
        if self.habery.inited and self.habery.free:
            self.habery.close(clear=self.habery.temp)


class BaseHab:
    """Hab class provides a given identifier controller's local resource environment
    i.e. hab or habitat. Includes dependency injection of database, keystore,
    configuration file as well as Kevery and key store Manager.

    Attributes:
        ks (Keeper): Injected. lmdb key store.
        db (basing.Baser): Injected. lmdb data base for KEL etc.
        cf (Configer): Injected. Config file instance.
        mgr (Manager): Injected. Creates and rotates keys in key store.
        rtr (Router): Injected. Routes reply ``rpy`` messages.
        rvy (Revery): Injected. Factory that processes reply ``rpy`` messages.
        kvy (Kevery): Injected. Factory for local processing of local event msgs.
        psr (Parser): Injected. Parses local messages for ``.kvy`` and ``.rvy``.
        name (str): Alias of controller.
        pre (str): qb64 prefix of own local controller, or None if new.
        temp (bool): True means testing; use weak level when salty algo for
            stretching in key creation for incept and rotate of keys for
            this ``hab.pre``.
        inited (bool): True means fully initialized wrt databases,
            False means not yet fully initialized.
        delpre (str or None): Delegator prefix if any, else None.
    """

    def __init__(self, ks, db, cf, mgr, rtr, rvy, kvy, psr, *,
                 name='test', ns=None, pre=None, temp=False):
        """Initialize instance.

        Args:
            ks (Keeper): lmdb key store.
            db (basing.Baser): lmdb data base for KEL etc.
            cf (Configer): config file instance.
            mgr (Manager): creates and rotates keys in key store.
            rtr (Router): routes reply ``rpy`` messages.
            rvy (Revery): factory that processes reply ``rpy`` messages.
            kvy (Kevery): factory for local processing of local event msgs.
            psr (Parser): parses local messages for ``.kvy`` and ``.rvy``.
            name (str): alias name for local controller of habitat.
            pre (str or None): qb64 identifier prefix of own local controller,
                else None.
            temp (bool): True means testing — use weak level when salty algo
                for stretching in key creation for incept and rotate of keys
                for this hab.pre.
        """
        self.db = db  # injected
        self.ks = ks  # injected
        self.cf = cf  # injected
        self.mgr = mgr  # injected
        self.rtr = rtr  # injected
        self.rvy = rvy  # injected
        self.kvy = kvy  # injected
        self.psr = psr  # injected

        self.name = name
        self.ns = ns  # what is this?
        self.pre = pre  # wait to setup until after db is known to be opened
        self.temp = True if temp else False

        self.inited = False
        self.delpre = None  # assigned laster if delegated

    def make(self, DnD, code, data, delpre, estOnly, isith, verfers, nsith, digers, toad, wits):
        """Creates Serder of inception event for provided parameters.
        Assumes injected dependencies were already setup.

        Args:
            DnD (bool): True means add trait ``TraitDex.DnD`` which means do
                not allow delegated identifiers from this identifier. False
                (default) means do allow, and no trait is added.
            code (str): prefix derivation code, default Blake3.
            data (list or None): seal dicts.
            delpre (str or None): qb64 of delegator identifier prefix if any.
            estOnly (bool or None): True means add trait ``TraitDex.EstOnly``
                which means only establishment events are allowed in the KEL
                for this Hab. False (default) means allow non-est events and
                no trait is added.
            isith (int, str, list, or None): incepting signing threshold as
                int, str hex, or list weighted if any, otherwise compute
                default from verfers.
            verfers (list[Verfer]): Verfer instances for initial signing keys.
            nsith (int, str, list, or None): next signing threshold as int,
                str hex, or list weighted if any, otherwise compute default
                from digers.
            digers (list[Diger] or None): Diger instances for next key digests.
            toad (int, str, or None): int or str hex of witness threshold if
                specified, else compute default based on number of wits
                (backers).
            wits (list or None): qb64 prefixes of witnesses if any.

        Returns:
            Serder: inception event serder.
        """
        icount = len(verfers)
        ncount = len(digers) if digers is not None else 0
        if isith is None:  # compute default
            isith = f"{max(1, ceil(icount / 2)):x}"
        if nsith is None:  # compute default
            nsith = f"{max(0, ceil(ncount / 2)):x}"
        cst = Tholder(sith=isith).sith  # current signing threshold
        nst = Tholder(sith=nsith).sith  # next signing threshold
        cnfg = []
        if estOnly:
            cnfg.append(TraitDex.EstOnly)
        if DnD:
            cnfg.append(TraitDex.DoNotDelegate)
        self.delpre = delpre
        keys = [verfer.qb64 for verfer in verfers]
        if self.delpre:
            serder = delcept(keys=keys,
                                      delpre=self.delpre,
                                      isith=cst,
                                      nsith=nst,
                                      ndigs=[diger.qb64 for diger in digers],
                                      toad=toad,
                                      wits=wits,
                                      cnfg=cnfg,
                                      code=code)
        else:
            serder = inceptEvent(keys=keys,
                                 isith=cst,
                                 nsith=nst,
                                 ndigs=[diger.qb64 for diger in digers],
                                 toad=toad,
                                 wits=wits,
                                 cnfg=cnfg,
                                 code=code,
                                 data=data)
        return serder

    def save(self, habord):
        self.db.habs.pin(keys=self.pre,
                         val=habord)
        ns = "" if self.ns is None else self.ns
        if self.db.names.get(keys=(ns, self.name)) is not None:
            raise ValueError("AID already exists with that name")

        self.db.names.pin(keys=(ns, self.name),
                          val=self.pre)

    def reconfigure(self):
        """Apply configuration from config file managed by ``.cf`` to this Hab.
        Assumes that ``.pre`` and signing keys have been set up in order to
        create own endpoint auth when provided in ``.cf``.

        Config file (JSON or HJSON) format:

        .. code-block:: json

            {
                "dt": "2021-01-01T00:00:00.000000+00:00",
                "nel": {
                    "dt": "2021-01-01T00:00:00.000000+00:00",
                    "curls": [
                        "tcp://localhost:5621/"
                    ]
                },
                "iurls": [
                    "tcp://localhost:5620/?role=peer&name=tam"
                ],
                "durls": [
                    "http://127.0.0.1:7723/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
                    "http://127.0.0.1:7723/oobi/EMhvwOlyEJ9kN4PrwCpr9Jsv7TxPhiYveZ0oP3lJzdEi"
                ],
                "wurls": [
                    "http://127.0.0.1:5644/.well-known/keri/oobi/EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy?name=Root"
                ]
            }

        Note:
            Config file is meant to be read only at init, not changed by the
            app at run time. Any dynamic app changes must go in the database,
            not the config file — that way we don't have to worry about
            multiple writers to ``.cf``. Use the config file to preload the
            database, not as a database. Config file may have named sections
            for Habery or individual Habs as needed.
        """

        conf = self.cf.get()
        if self.name not in conf:
            return

        conf = conf[self.name]
        if "dt" in conf:  # datetime of config file
            dt = fromIso8601(conf["dt"])  # raises error if not convert
            msgs = bytearray()
            msgs.extend(self.makeEndRole(eid=self.pre,
                                         role=Roles.controller,
                                         stamp=toIso8601(dt=dt)))
            if "curls" in conf:
                curls = conf["curls"]
                for url in curls:
                    splits = urlsplit(url)
                    scheme = (splits.scheme if splits.scheme in Schemes
                              else Schemes.http)
                    msgs.extend(self.makeLocScheme(url=url,
                                                   scheme=scheme,
                                                   stamp=toIso8601(dt=dt)))
            self.psr.parse(ims=msgs)

    @property
    def iserder(self):
        """Return serder of inception event.

        Returns:
            SerderKERI: own inception event serder.

        Raises:
            ConfigurationError: if inception event is missing from the KEL or
                the event store.
        """
        if (dig := self.db.kels.getLast(keys=self.pre, on=0)) is None:
            raise ConfigurationError("Missing inception event in KEL for "
                                            "Habitat pre={}.".format(self.pre))
        dig = dig.encode("utf-8")
        if (serder := self.db.evts.get(keys=(self.pre, bytes(dig)))) is None:
            raise ConfigurationError("Missing inception event for "
                                            "Habitat pre={}.".format(self.pre))
        return serder

    @property
    def kevers(self):
        """Returns ``.db.kevers``.

        Returns:
            dict: mapping of qb64 prefix to Kever instances.
        """
        return self.db.kevers

    @property
    def accepted(self):
        """True if own prefix has been accepted into the local KEL.

        Returns:
            bool: True if ``.pre`` is in ``.kevers``, False otherwise.
        """
        return self.pre in self.kevers

    @property
    def kever(self):
        """Returns kever for own ``.pre``.

        Returns:
            Kever or None: Kever instance if accepted, else None.
        """
        return self.kevers[self.pre] if self.accepted else None

    @property
    def prefixes(self):
        """Returns ``.db.prefixes``.

        Returns:
            OrderedSet: local prefixes for ``.db``.
        """
        return self.db.prefixes

    def incept(self, **kwa):
        """Alias for ``.make``.

        Args:
            **kwa: keyword arguments forwarded to :meth:`make`.
        """
        self.make(**kwa)

    def rotate(self, *, verfers=None, digers=None, isith=None, nsith=None, toad=None, cuts=None, adds=None,
               data=None):
        """Perform rotation operation. Register rotation in database.

        Args:
            verfers (list or None): Verfer instances of public keys qb64.
            digers (list or None): Diger instances of public next key digests
                qb64.
            isith (int, str, or None): current signing threshold as int, str
                hex, or list of str weights. Default is prior next sith.
            nsith (int, str, or None): next signing threshold as int, str hex,
                or list of str weights. Default is based on isith when None.
            toad (int or str or None): hex of witness threshold after cuts and
                adds.
            cuts (list or None): qb64 prefixes of witnesses to be removed from
                the witness list.
            adds (list or None): qb64 prefixes of witnesses to be added to the
                witness list.
            data (list or None): dicts of committed data such as seals.

        Returns:
            bytearray: rotation message with attached signatures.

        Raises:
            ValidationError: if the new key set cannot satisfy the prior next
                signing threshold, or if the rotation event is otherwise
                improper.
        """
        # recall that kever.pre == self.pre
        kever = self.kever  # before rotation kever is prior next

        if isith is None:
            isith = kever.ntholder.sith  # use prior next sith as default
        if nsith is None:
            nsith = isith  # use new current as default
        if toad is None and not cuts and not adds:
            toad = kever.toader.num  # preserve prior toad when no witness changes

        if isith is None:  # compute default from newly rotated verfers above
            isith = f"{max(1, ceil(len(verfers) / 2)):x}"
        if nsith is None:  # compute default from newly rotated digers above
            nsith = f"{max(0, ceil((len(digers) if digers is not None else 0) / 2)):x}"

        cst = Tholder(sith=isith).sith  # current signing threshold
        nst = Tholder(sith=nsith).sith  # next signing threshold

        keys = [verfer.qb64 for verfer in verfers]

        indices = []
        for idx, diger in enumerate(kever.ndigers):
            pdigs = [Diger(ser=verfer.qb64b, code=diger.code).qb64 for verfer in verfers]
            if diger.qb64 in pdigs:
                indices.append(idx)

        if not kever.ntholder.satisfy(indices):
            raise ValidationError("invalid rotation, new key set unable to satisfy prior next signing threshold")

        if kever.delpre is not None:  # delegator only shows up in delcept
            serder = deltate(pre=kever.prefixer.qb64,
                                      keys=keys,
                                      dig=kever.serder.said,
                                      sn=kever.sner.num + 1,
                                      isith=cst,
                                      nsith=nst,
                                      ndigs=[diger.qb64 for diger in digers],
                                      toad=toad,
                                      wits=kever.wits,
                                      cuts=cuts,
                                      adds=adds,
                                      data=data)
        else:
            serder = rotateEvent(pre=kever.prefixer.qb64,
                                     keys=keys,
                                     dig=kever.serder.said,
                                     sn=kever.sner.num + 1,
                                     isith=cst,
                                     nsith=nst,
                                     ndigs=[diger.qb64 for diger in digers],
                                     toad=toad,
                                     wits=kever.wits,
                                     cuts=cuts,
                                     adds=adds,
                                     data=data)

        # sign handles group hab with .mhab case
        sigers = self.sign(ser=serder.raw, verfers=verfers, rotated=True)

        # update own key event verifier state
        msg = messagize(serder, sigers=sigers)

        try:
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except MissingSignatureError:
            pass
        except Exception as ex:
            raise ValidationError("Improper Habitat rotation for "
                                         "pre={self.pre}.") from ex

        return msg

    def interact(self, *, data=None):
        """Perform interaction operation. Register interaction in database.

        Args:
            data (list or None): dicts of committed data such as seals.

        Returns:
            bytearray: interaction message with attached signatures.

        Raises:
            ValidationError: if the interaction event is improper.
        """
        kever = self.kever
        serder = interactEvent(pre=kever.prefixer.qb64,
                                   dig=kever.serder.said,
                                   sn=kever.sner.num + 1,
                                   data=data)

        sigers = self.sign(ser=serder.raw)

        msg = messagize(serder, sigers=sigers)
        try:
            # verify event, update kever state, and escrow if group
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except MissingSignatureError:
            pass
        except Exception as ex:
            raise ValidationError("Improper Habitat interaction for "
                                         "pre={}.".format(self.pre)) from ex

        return msg


    def sign(self, ser, verfers=None, indexed=True, indices=None, ondices=None, **kwa):
        """Sign given serialization ``ser`` using appropriate keys.
        Uses provided verfers or ``.kever.verfers`` to look up keys to sign.

        Args:
            ser (bytes): serialization to sign.
            verfers (list[Verfer] or None): Verfer instances to get public
                verifier keys to look up private signing keys. None means use
                ``.kever.verfers``. When group and verfers is not None, the
                provided verfers must be ``.kever.verfers``.
            indexed (bool): when not mhab, True means use indexed signatures
                and return a list of Siger instances. False means do not use
                indexed signatures and return a list of Cigar instances.
            indices (list[int] or None): indices (offsets) when
                ``indexed`` is True. See ``Manager.sign``.
            ondices (list[int or None] or None): other indices (offsets) when
                ``indexed`` is True. See ``Manager.sign``.

        Returns:
            list[Siger] or list[Cigar]: signed instances depending on
            ``indexed``.
        """
        if verfers is None:
            verfers = self.kever.verfers  # when group these provide group signing keys

        return self.mgr.sign(ser=ser,
                             verfers=verfers,
                             indexed=indexed,
                             indices=indices,
                             ondices=ondices)


    def decrypt(self, ser, verfers=None, **kwa):
        """Decrypt given serialization ``ser`` using appropriate keys.
        Uses provided verfers or ``.kever.verfers`` to look up keys to decrypt.

        Args:
            ser (str, bytes, bytearray, or memoryview): serialization to
                decrypt.
            verfers (list[Verfer] or None): Verfer instances to get public
                verifier keys to look up and convert to private decryption
                keys. None means use ``.kever.verfers``. When group and
                verfers is not None, the provided verfers must be
                ``.kever.verfers``.

        Returns:
            bytes: decrypted serialization.
        """
        if verfers is None:
            verfers = self.kever.verfers  # when group these provide group signing keys

        # should not use mgr.decrypt since it assumes qb64. Just lucky its not
        # yet a problem
        return self.mgr.decrypt(qb64=ser, verfers=verfers)


    def query(self, pre, src, query=None, **kwa):
        """Create, sign, and return a ``qry`` message against the attester
        for the prefix.

        Args:
            pre (str): qb64 identifier prefix being queried for.
            src (str): qb64 identifier prefix of attester being queried.
            query (dict or None): additional query modifiers to include in
                ``q``.
            **kwa: keyword arguments passed to ``queryEvent``.

        Returns:
            bytearray: signed query event.
        """

        query = query if query is not None else dict()
        query['i'] = pre
        query["src"] = src
        serder = queryEvent(query=query, **kwa)
        return self.endorse(serder, last=True)

    def endorse(self, serder, last=False, pipelined=True):
        """Return msg with own endorsement of msg from serder with attached
        signature groups based on own pre transferable or non-transferable.

        Args:
            serder (Serder): instance of msg.
            last (bool): True means use SealLast. False means use SealEvent.
                Query messages use SealLast.
            pipelined (bool): True means use pipelining attachment code.

        Returns:
            bytearray: endorsed message with attached signatures.
        """
        if self.kever.prefixer.transferable:
            # create SealEvent or SealLast for endorser's est evt whose keys are
            # used to sign
            kever = self.kever

            if last:
                seal = SealLast(i=kever.prefixer.qb64)
            else:
                seal = SealEvent(i=kever.prefixer.qb64,
                                          s="{:x}".format(kever.lastEst.s),
                                          d=kever.lastEst.d)

            sigers = self.sign(ser=serder.raw,
                               indexed=True)

            msg = messagize(serder=serder,
                                     sigers=sigers,
                                     seal=seal,
                                     pipelined=pipelined)

        else:
            cigars = self.sign(ser=serder.raw,
                               indexed=False)
            msg = messagize(serder=serder,
                                     cigars=cigars,
                                     pipelined=pipelined)

        return msg

    def exchange(self, route,
                 payload,
                 recipient,
                 date=None,
                 eid=None,
                 dig=None,
                 modifiers=None,
                 embeds=None,
                 save=False):
        """Build and return a signed ``exn`` message, optionally saving it to
        own db.

        Args:
            route (str): route path string indicating the data flow handler.
            payload (dict): payload data for the exchange message.
            recipient (str): qb64 identifier prefix of the recipient.
            date (str or None): date-time-stamp string. None means use now.
            eid (str or None): qb64 of endpoint provider identifier if any.
            dig (str or None): qb64 digest if any.
            modifiers (dict or None): additional modifiers for the exchange.
            embeds (dict or None): embedded message serders if any.
            save (bool): True means process local copy into db after building.

        Returns:
            bytearray: signed exchange message with count code and receipt
            couples (pre+cig).
        """
        # sign serder event

        serder, end = exchange(route=route,
                               payload=payload,
                               sender=self.pre,
                               recipient=recipient,
                               date=date,
                               dig=dig,
                               modifiers=modifiers,
                               embeds=embeds)

        if self.kever.prefixer.transferable:
            msg = self.endorse(serder=serder, pipelined=False)
        else:
            cigars = self.sign(ser=serder.raw,
                               indexed=False)
            msg = messagize(serder, cigars=cigars)

        msg.extend(end)

        if save:
            self.psr.parseOne(ims=bytearray(msg))  # process local copy into db

        return msg

    def receipt(self, serder):
        """Build own receipt ``rct`` message of serder with count code and
        receipt couples (pre+cig). Processes local copy into db to validate.

        Args:
            serder (Serder): event serder to receipt.

        Returns:
            bytearray: receipt message with attached signatures.
        """
        ked = serder.ked
        reserder = receiptEvent(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    said=serder.said)

        # sign serder event
        if self.kever.prefixer.transferable:
            seal = SealEvent(i=self.pre,
                                      s="{:x}".format(self.kever.lastEst.s),
                                      d=self.kever.lastEst.d)
            sigers = self.sign(ser=serder.raw,
                               indexed=True)
            msg = messagize(serder=reserder, sigers=sigers, seal=seal)
        else:
            cigars = self.sign(ser=serder.raw,
                               indexed=False)
            msg = messagize(reserder, cigars=cigars)

        self.psr.parseOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def witness(self, serder):
        """Build own witness receipt ``rct`` message of serder with count code
        and witness indexed receipt signatures, if the key state of
        ``serder.pre`` shows that own pre is a current witness of the event in
        serder.

        Note:
            The caller must ensure that the serder being witnessed has been
            accepted as a valid event into this hab controller's KEL before
            calling this method.

        Args:
            serder (Serder): event serder to witness.

        Returns:
            bytearray: witness receipt message with attached signatures.

        Raises:
            ValueError: if own prefix is transferable, if the key state for
                ``serder.pre`` is missing, or if own prefix is not a witness
                of the event.
        """
        if self.kever.prefixer.transferable:  # not non-transferable prefix
            raise ValueError("Attempt to create witness receipt with"
                             " transferable pre={}.".format(self.pre))
        ked = serder.ked

        if serder.pre not in self.kevers:
            raise ValueError("Attempt by {} to witness event with missing key "
                             "state.".format(self.pre))
        kever = self.kevers[serder.pre]
        if self.pre not in kever.wits:
            print("Attempt by {} to witness event of {} when not a "
                  "witness in wits={}.".format(self.pre,
                                               serder.pre,
                                               kever.wits))
        index = kever.wits.index(self.pre)

        reserder = receiptEvent(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    said=serder.said)

        # assumes witness id is nontrans so public key is same as pre
        wigers = self.mgr.sign(ser=serder.raw,
                               pubs=[self.pre],
                               indices=[index])

        msg = messagize(reserder, wigers=wigers, pipelined=True)
        self.psr.parseOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def replay(self, pre=None, fn=0):
        """Return replay of FEL (first-seen event log) for ``pre`` starting
        from ``fn``. Default pre is own ``.pre``.

        Args:
            pre (str or None): qb64 str or bytes of identifier prefix.
                Default is own ``.pre``.
            fn (int): first-seen ordering number to start from.

        Returns:
            bytearray: serialized event log messages.
        """
        if not pre:
            pre = self.pre

        msgs = bytearray()
        kever = self.kevers[pre]
        for msg in self.db.cloneDelegation(kever=kever):
            msgs.extend(msg)

        for msg in self.db.clonePreIter(pre=pre, fn=fn):
            msgs.extend(msg)

        return msgs


    def replayAll(self):
        """Return replay of FEL (first-seen event log) for all prefixes.

        Returns:
            bytearray: serialized event log messages for all prefixes.
        """
        msgs = bytearray()
        for msg in self.db.cloneAllPreIter():
            msgs.extend(msg)
        return msgs


    def makeOtherEvent(self, pre, sn):
        """Return messagized bytearray message with attached signatures of
        the event at sequence number ``sn`` for ``pre``, retrieved from the
        database.

        Args:
            pre (str): qb64 identifier prefix.
            sn (int): sequence number of event.

        Returns:
            bytearray or None: messagized event with attached signatures,
            or None if ``pre`` is not in kevers.

        Raises:
            MissingEntryError: if no event is found for ``pre`` at ``sn``.
        """
        if pre not in self.kevers:
            return None

        msg = bytearray()
        dig = self.db.kels.getLast(keys=pre, on=sn)
        if dig is None:
            raise MissingEntryError("Missing event for pre={} at sn={}."
                                           "".format(pre, sn))
        dig = dig.encode("utf-8")
        dig = bytes(dig)
        serder = self.db.evts.get(keys=(pre, dig))
        msg.extend(serder.raw)
        msg.extend(Counter(Codens.ControllerIdxSigs, count=self.db.sigs.cnt(keys=(pre, dig)),
                           version=Vrsn_1_0).qb64b)  # attach cnt
        for siger in self.db.sigs.getIter(keys=(pre, dig)):
            msg.extend(siger.qb64b)  # attach siger
        return msg


    def fetchEnd(self, cid: str, role: str, eid: str):
        """Return the endpoint record for the given controller, role, and
        endpoint provider.

        Args:
            cid (str): qb64 identifier prefix of controller.
            role (str): endpoint role.
            eid (str): qb64 identifier prefix of endpoint provider.

        Returns:
            EndpointRecord or None: endpoint record instance, or None if not
            found.
        """
        return self.db.ends.get(keys=(cid, role, eid))


    def fetchLoc(self, eid: str, scheme: str = Schemes.http):
        """Return the location record for the given endpoint provider and
        scheme.

        Args:
            eid (str): qb64 identifier prefix of endpoint provider.
            scheme (str): url scheme. Default is ``Schemes.http``.

        Returns:
            LocationRecord or None: location record instance, or None if not
            found.
        """
        return self.db.locs.get(keys=(eid, scheme))


    def fetchEndAllowed(self, cid: str, role: str, eid: str):
        """Return whether ``eid`` is allowed as endpoint provider for ``cid``
        in ``role``.

        Args:
            cid (str): qb64 identifier prefix of controller authorizing
                endpoint provider ``eid`` in role.
            role (str): endpoint role such as controller, witness, watcher,
                etc.
            eid (str): qb64 identifier prefix of endpoint provider in role.

        Returns:
            bool or None: True if ``eid`` is allowed, False if not, None if
            no endpoint record exists.
        """
        end = self.db.ends.get(keys=(cid, role, eid))
        return end.allowed if end else None


    def fetchEndEnabled(self, cid: str, role: str, eid: str):
        """Return whether ``eid`` is enabled as endpoint provider for ``cid``
        in ``role``.

        Args:
            cid (str): qb64 identifier prefix of controller authorizing
                endpoint provider ``eid`` in role.
            role (str): endpoint role such as controller, witness, watcher,
                etc.
            eid (str): qb64 identifier prefix of endpoint provider in role.

        Returns:
            bool or None: True if ``eid`` is enabled, False if not, None if
            no endpoint record exists.
        """
        end = self.db.ends.get(keys=(cid, role, eid))
        return end.enabled if end else None


    def fetchEndAuthzed(self, cid: str, role: str, eid: str):
        """Return whether ``eid`` is authorized (enabled or allowed) as
        endpoint provider for ``cid`` in ``role``.

        Args:
            cid (str): qb64 identifier prefix of controller authorizing
                endpoint provider ``eid`` in role.
            role (str): endpoint role such as controller, witness, watcher,
                etc.
            eid (str): qb64 identifier prefix of endpoint provider in role.

        Returns:
            bool or None: True if ``eid`` is enabled or allowed, False if
            neither, None if no endpoint record exists.
        """
        end = self.db.ends.get(keys=(cid, role, eid))
        return (end.enabled or end.allowed) if end else None


    def fetchUrl(self, eid: str, scheme: str = Schemes.http):
        """Return the url for the endpoint provider given by ``eid``.

        Args:
            eid (str): qb64 identifier prefix of endpoint provider.
            scheme (str): url scheme. Default is ``Schemes.http``.

        Returns:
            str or None: url string for the endpoint provider (empty string
            when url is nullified), or None when no location record exists.
        """
        loc = self.db.locs.get(keys=(eid, scheme))
        return loc.url if loc else loc


    def fetchUrls(self, eid: str, scheme: str = ""):
        """Return urls keyed by scheme for the given ``eid``.

        Note:
            The caller is responsible for independently verifying that ``eid``
            is allowed for a given ``cid`` and role. Entries with empty urls
            are excluded from the result.

        Args:
            eid (str): qb64 identifier prefix of endpoint provider.
            scheme (str): url scheme filter. Empty string means all schemes.

        Returns:
            hicting.Mict: urls keyed by scheme for the given ``eid``.
        """
        return hicting.Mict([(keys[1], loc.url) for keys, loc in
                             self.db.locs.getTopItemIter(keys=(eid, scheme)) if loc.url])


    def fetchRoleUrls(self, cid: str, *, role: str = "", scheme: str = "",
                      eids=None, enabled: bool = True, allowed: bool = True):
        """Return nested dicts of role -> eid -> scheme -> url for the given ``cid``.

        Args:
            cid (str): qb64 identifier prefix of the controller authorizing
                endpoint provider ``eid`` in role.
            role (str): endpoint role filter (e.g. ``controller``, ``witness``,
                ``watcher``). Empty string means all roles.
            scheme (str): url scheme filter. Empty string means all schemes.
            eids (list or None): when provided, restrict results to only eids
                in this list.
            enabled (bool): True means include enabled endpoint providers.
            allowed (bool): True means include allowed endpoint providers.

        Returns:
            hicting.Mict: nested Mict keyed as ``rurls[role][eid][scheme]``,
                where each leaf value is a url string.
        """
        if eids is None:
            eids = []

        rurls = hicting.Mict()

        if role == Roles.witness:
            if kever := self.kevers[cid] if cid in self.kevers else None:
                # latest key state for cid
                for eid in kever.wits:
                    if not eids or eid in eids:
                        surls = self.fetchUrls(eid, scheme=scheme)
                        if surls:
                            rurls.add(Roles.witness,
                                      hicting.Mict([(eid, surls)]))

        for (_, erole, eid), end in self.db.ends.getTopItemIter(keys=(cid, role)):
            if (enabled and end.enabled) or (allowed and end.allowed):
                if not eids or eid in eids:
                    surls = self.fetchUrls(eid, scheme=scheme)
                    if surls:
                        rurls.add(erole, hicting.Mict([(eid, surls)]))
        return rurls


    def fetchWitnessUrls(self, cid: str, scheme: str = "", eids=None,
                         enabled: bool = True, allowed: bool = True):
        """Fetch witness urls for witnesses of ``cid`` at latest key state,
        or enabled/allowed witnesses if not a witness at latest key state.

        Args:
            cid (str): qb64 identifier prefix of controller whose witnesses
                are being fetched.
            scheme (str): url scheme filter. Empty string means all schemes.
            eids (list or None): when provided, restrict results to only eids
                in this list.
            enabled (bool): True means include enabled witnesses.
            allowed (bool): True means include allowed witnesses.

        Returns:
            hicting.Mict: nested Mict keyed as ``rurls[role][eid][scheme]``,
                where each leaf value is a url string. Role is always
                ``witness`` for results from this method.
        """
        return (self.fetchRoleUrls(cid=cid,
                                   role=Roles.witness,
                                   scheme=scheme,
                                   eids=eids,
                                   enabled=enabled,
                                   allowed=allowed))


    def endsFor(self, pre):
        """Load authorized endpoints for the provided AID.

        Args:
            pre (str): qb64 aid for which to load ends.

        Returns:
            dict: nested dict of role -> eid -> scheme -> endpoint.
        """
        ends = dict()

        for (_, erole, eid), end in self.db.ends.getTopItemIter(keys=(pre,)):
            locs = dict()
            urls = self.fetchUrls(eid=eid, scheme="")
            for rscheme, url in urls.firsts():
                locs[rscheme] = url

            if erole not in ends:
                ends[erole] = dict()

            ends[erole][eid] = locs

        witrolls = dict()
        if kever := self.kevers[pre] if pre in self.kevers else None:
            for eid in kever.wits:
                locs = dict()
                urls = self.fetchUrls(eid=eid, scheme="")
                for rscheme, url in urls.firsts():
                    locs[rscheme] = url

                witrolls[eid] = locs

        if len(witrolls) > 0:
            ends[Roles.witness] = witrolls

        return ends


    def reply(self, **kwa):
        """Return own endorsed reply message.

        Args:
            **kwa: keyword arguments forwarded to ``replyEvent``, including:
                route (str): route path string indicating the data flow handler.
                data (list): dicts of committed data such as seals.
                dts (str): date-time-stamp of message at time of creation.
                version (Version): version instance.
                kind (str): serialization kind.

        Returns:
            bytearray: reply message.
        """
        return self.endorse(replyEvent(**kwa))


    def makeEndRole(self, eid, role=Roles.controller, allow=True, stamp=None):
        """Return a reply message allowing or disallowing endpoint provider
        ``eid`` in ``role``.

        Args:
            eid (str): qb64 of endpoint provider to be authorized.
            role (str): authorized role for ``eid``. Default is
                ``Roles.controller``.
            allow (bool): True means add ``eid`` at ``role`` as authorized.
                False means cut ``eid`` at ``role`` as unauthorized.
            stamp (str or None): date-time-stamp RFC-3339 profile of iso8601
                datetime. None means use now.

        Returns:
            bytearray: reply message.
        """
        data = dict(cid=self.pre, role=role, eid=eid)
        route = "/end/role/add" if allow else "/end/role/cut"
        return self.reply(route=route, data=data, stamp=stamp)


    def loadEndRole(self, cid, eid, role=Roles.controller):
        """Load and return the messagized end role authorization record for
        the given ``cid``, ``eid``, and ``role`` from the database, including
        associated attachments.

        Args:
            cid (str): qb64 identifier prefix of controller.
            eid (str): qb64 identifier prefix of endpoint provider.
            role (str): endpoint role. Default is ``Roles.controller``.

        Returns:
            bytearray: messagized end role record with attachments, or empty
            bytearray if not found or not enabled/allowed.
        """
        msgs = bytearray()
        end = self.db.ends.get(keys=(cid, role, eid))
        if end and (end.enabled or end.allowed):
            said = self.db.eans.get(keys=(cid, role, eid))
            serder = self.db.rpys.get(keys=(said.qb64,))
            cigars = self.db.scgs.get(keys=(said.qb64,))
            tsgs = fetchTsgs(db=self.db.ssgs, diger=said)

            if len(cigars) == 1:
                (verfer, cigar) = cigars[0]
                cigar.verfer = verfer
            else:
                cigar = None

            if len(tsgs) > 0:
                (prefixer, seqner, diger, sigers) = tsgs[0]
                seal = SealEvent(i=prefixer.qb64,
                                          s=seqner.snh,
                                          d=diger.qb64)
            else:
                sigers = None
                seal = None

            msgs.extend(messagize(serder=serder,
                                           cigars=[cigar] if cigar else [],
                                           sigers=sigers,
                                           seal=seal,
                                           pipelined=True))
        return msgs


    def makeLocScheme(self, url, eid=None, scheme="http", stamp=None):
        """Return a reply message of own url service endpoint at ``scheme``.

        Args:
            url (str): url of endpoint. May have scheme missing or not. An
                empty url nullifies the location.
            eid (str or None): qb64 of endpoint provider to be authorized.
                None means use own ``.pre``.
            scheme (str): url scheme; must match scheme in url if present.
                Default is ``"http"``.
            stamp (str or None): date-time-stamp RFC-3339 profile of iso8601
                datetime. None means use now.

        Returns:
            bytearray: reply message.
        """
        eid = eid if eid is not None else self.pre
        data = dict(eid=eid, scheme=scheme, url=url)
        return self.reply(route="/loc/scheme", data=data, stamp=stamp)


    def replyLocScheme(self, eid, scheme=""):
        """Return a reply message stream of location scheme entries authed by
        the given ``eid`` from the reply database, including associated
        attachments, for dissemination of BADA reply data authentication
        proofs.

        Note:
            Currently uses a promiscuous model for permitting endpoint
            discovery. Future versions will use an identity constraint graph
            to constrain discovery.

        Args:
            eid (str): endpoint provider id.
            scheme (str): url scheme filter. Empty string means all schemes.

        Returns:
            bytearray: reply message stream for location scheme entries.
        """
        msgs = bytearray()

        urls = self.fetchUrls(eid=eid, scheme=scheme)
        for rscheme, url in urls.firsts():
            msgs.extend(self.makeLocScheme(eid=eid, url=url, scheme=rscheme))

        return msgs


    def loadLocScheme(self, eid, scheme=None):
        """Load and return messagized location scheme records for the given
        ``eid`` and optional ``scheme`` from the database, including associated
        attachments.

        Args:
            eid (str): qb64 identifier prefix of endpoint provider.
            scheme (str or None): url scheme filter. None means all schemes.

        Returns:
            bytearray: messagized location scheme records with attachments.
        """
        msgs = bytearray()
        keys = (eid, scheme) if scheme else (eid,)
        for (pre, _), said in self.db.lans.getTopItemIter(keys=keys):
            serder = self.db.rpys.get(keys=(said.qb64,))
            cigars = self.db.scgs.get(keys=(said.qb64,))
            tsgs = fetchTsgs(db=self.db.ssgs, diger=said)

            if len(cigars) == 1:
                (verfer, cigar) = cigars[0]
                cigar.verfer = verfer
            else:
                cigar = None

            if len(tsgs) > 0:
                (prefixer, seqner, diger, sigers) = tsgs[0]
                seal = SealEvent(i=prefixer.qb64,
                                          s=seqner.snh,
                                          d=diger.qb64)
            else:
                sigers = None
                seal = None

            msgs.extend(messagize(serder=serder,
                                           cigars=[cigar] if cigar else [],
                                           sigers=sigers,
                                           seal=seal,
                                           pipelined=True))
        return msgs


    def replyEndRole(self, cid, role=None, eids=None, scheme=""):
        """Return a reply message stream of end role authorization entries
        authed by the given ``cid`` from the reply database, including
        associated attachments, for dissemination of BADA reply data
        authentication proofs.

        Note:
            Currently uses a promiscuous model for permitting endpoint
            discovery. Future versions will use an identity constraint graph
            to constrain discovery.

        Behavior by argument combination:

        - ``cid`` only: end authz for all eids in all roles and loc url for
          all schemes at each eid (filtered by ``eids`` if provided).
        - ``cid`` + ``scheme``: end authz for all eids in all roles and loc
          url for ``scheme`` at each eid.
        - ``cid`` + ``role``: end authz for all eids in ``role`` and loc url
          for all schemes at each eid.
        - ``cid`` + ``role`` + ``scheme``: end authz for all eids in ``role``
          and loc url for ``scheme`` at each eid.

        Args:
            cid (str): qb64 identifier prefix of controller authorizing
                endpoint provider ``eid``.
            role (str or None): endpoint role filter. None means all roles.
            eids (list or None): when provided, restrict results to only eids
                in this list.
            scheme (str): url scheme filter. Empty string means all schemes.

        Returns:
            bytearray: reply message stream for end role entries.
        """
        msgs = bytearray()

        if eids is None:
            eids = []

        if cid not in self.kevers:
            return msgs

        msgs.extend(self.replay(cid))

        kever = self.kevers[cid]
        witness = self.pre in kever.wits  # see if we are cid's witness

        if role == Roles.witness:
            # latest key state for cid
            for eid in kever.wits:
                if not eids or eid in eids:
                    if eid == self.pre:
                        msgs.extend(self.replyLocScheme(eid=eid, scheme=scheme))
                    else:
                        msgs.extend(self.loadLocScheme(eid=eid, scheme=scheme))
                    if not witness:  # we are not witness, send auth records
                        msgs.extend(self.makeEndRole(eid=eid, role=role))

        for (_, erole, eid), end in self.db.ends.getTopItemIter(keys=(cid,)):
            if (end.enabled or end.allowed) and (not role or role == erole) and (not eids or eid in eids):
                msgs.extend(self.loadLocScheme(eid=eid, scheme=scheme))
                msgs.extend(self.loadEndRole(cid=cid, eid=eid, role=erole))

        return msgs


    def replyToOobi(self, aid, role, eids=None):
        """Return a reply message stream of entries authed by the given ``aid``
        for OOBI-initiated endpoint discovery, including associated
        attachments, for dissemination of BADA reply data authentication
        proofs.

        Note:
            Currently uses a promiscuous model for permitting OOBI-initiated
            endpoint discovery. Future versions will use an identity constraint
            graph to constrain discovery.

            This method is the entry point for initiating replies generated by
            :meth:`replyEndRole` and/or :meth:`replyLocScheme`.

        Args:
            aid (str): qb64 of identifier in oobi; may be cid or eid.
            role (str): authorized role for eid.
            eids (list or None): when provided, restrict results to only eids
                in this list.

        Returns:
            bytearray: reply message stream for OOBI endpoint entries.
        """
        # default logic is that if self.pre is witness of aid and has a loc url
        # for self then reply with loc scheme for all witnesses even if self
        # not permiteed in .habs.oobis
        return self.replyEndRole(cid=aid, role=role, eids=eids)


    def getOwnEvent(self, sn, allowPartiallySigned=False):
        """Return the event serder, controller signatures, and seal source
        duple for own event at sequence number ``sn``.

        Args:
            sn (int): sequence number of event.
            allowPartiallySigned (bool): True means attempt to load from
                partial signed escrow if not found in KEL.

        Returns:
            tuple: ``(serder, sigers, duple)`` where ``serder`` is the event
            Serder, ``sigers`` is a list of Siger instances, and ``duple`` is
            the seal source couple or None.

        Raises:
            MissingEntryError: if no event is found for own prefix at ``sn``.
        """
        dig = self.db.kels.getLast(keys=self.pre, on=sn)
        dig = dig.encode("utf-8") if dig else None
        if dig is None and allowPartiallySigned:
            vals = self.db.pses.getLast(keys=self.pre, on=sn)
            dig = vals.encode("utf-8") if vals else None

        if dig is None:
            raise MissingEntryError("Missing event for pre={} at sn={}."
                                           "".format(self.pre, sn))
        serder = self.db.evts.get(keys=(self.pre, dig))
        sigers = self.db.sigs.get(keys=(self.pre, dig))
        duple = self.db.aess.get(keys=(self.pre, dig))

        return serder, sigers, duple


    def makeOwnEvent(self, sn, allowPartiallySigned=False):
        """Messagize own event at ``sn`` with attachments if any.

        Args:
            sn (int): sequence number of event.
            allowPartiallySigned (bool): True means attempt to load from
                partial signed escrow if not found in KEL.

        Returns:
            bytearray: qb64b serialization of own event at ``sn`` with
            optionally attached signatures and seal source couple.
        """
        msg = bytearray()
        serder, sigs, duple = self.getOwnEvent(sn=sn,
                                                allowPartiallySigned=allowPartiallySigned)
        msg.extend(serder.raw)
        msg.extend(Counter(Codens.ControllerIdxSigs, count=len(sigs),
                           version=Vrsn_1_0).qb64b)  # attach cnt
        for sig in sigs:
            msg.extend(sig.qb64b)  # attach sig

        if duple is not None:
            seqner, diger = duple
            msg.extend(Counter(Codens.SealSourceCouples, count=1,
                               version=Vrsn_1_0).qb64b)
            msg.extend(seqner.qb64b + diger.qb64b)

        return msg


    def makeOwnInception(self, allowPartiallySigned=False):
        """Return messagized own inception event with attached signatures,
        retrieved from the database.

        Args:
            allowPartiallySigned (bool): True means attempt to load from
                partial signed escrow if not found in KEL.

        Returns:
            bytearray: messagized inception event with attached signatures.
        """
        return self.makeOwnEvent(sn=0, allowPartiallySigned=allowPartiallySigned)


    def processCues(self, cues):
        """Return bytearray of messages resulting from processing all cues.

        Args:
            cues (deque): cue dicts to process.

        Returns:
            bytearray: concatenated outgoing messages.
        """
        msgs = bytearray()  # outgoing messages
        for msg in self.processCuesIter(cues):
            msgs.extend(msg)
        return msgs


    def processCuesIter(self, cues):
        """Iterate through cues and yield one or more msgs for each cue.

        Args:
            cues (deque): cue dicts to process.

        Yields:
            bytearray: message(s) produced for each cue.
        """
        while cues:  # iteratively process each cue in cues
            msgs = bytearray()
            cue = cues.pull()  # cues.popleft()
            cueKin = cue["kin"]  # type or kind of cue

            if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                cuedSerder = cue["serder"]  # Serder of received event for other pre
                cuedKed = cuedSerder.ked
                cuedPrefixer = Prefixer(qb64=cuedKed["i"])
                logger.info("%s got cue: kin=%s%s", self.pre, cueKin,
                            cuedSerder.said)
                logger.debug(f"event=\n{cuedSerder.pretty()}\n")

                if cuedKed["t"] == Ilks.icp:
                    dgkey = dgKey(self.pre, self.iserder.said)
                    found = False
                    if cuedPrefixer.transferable:  # find if have rct from other pre for own icp
                        for sprefixer, snumber, sdiger, siger in self.db.vrcs.getIter(dgkey):
                            if sprefixer.qb64 == cuedKed["i"]:
                                found = True
                    else:  # find if already rcts of own icp
                        for prefixer, cigar in self.db.rcts.getIter(dgkey):
                            if prefixer.qb64.startswith(cuedKed["i"]):
                                found = True  # yes so don't send own inception

                    if not found:  # no receipt from remote so send own inception
                        # no vrcs or rct of own icp from remote so send own inception
                        msgs.extend(self.makeOwnInception())

                msgs.extend(self.receipt(cuedSerder))
                yield msgs

            elif cueKin in ("replay",):
                msgs = cue["msgs"]
                yield msgs

            elif cueKin in ("reply",):
                data = cue["data"]
                route = cue["route"]
                msg = self.reply(data=data, route=route)
                yield msg

            elif cueKin in ("witness",):  # cue to witness a received event, own pre must be a witness
                cuedSerder = cue["serder"]
                logger.info("%s got cue: kin=%s %s", self.pre, cueKin,
                            cuedSerder.said)
                logger.debug(f"event=\n{cuedSerder.pretty()}\n")
                msgs.extend(self.witness(cuedSerder))
                yield msgs

            elif cueKin in ("query",):  # cue to send a query message
                pre = cue["pre"]
                src = cue["src"]
                route = cue.get("route")
                query = cue.get("query")
                kwa = dict()
                if route is not None:
                    kwa["route"] = route
                msg = self.query(pre=pre, src=src, query=query, **kwa)
                yield msg

            elif cueKin in ("notice",):  # cue to notify of new own event accepted into KEL
                cuedSerder = cue["serder"]
                logger.info("%s got cue: kin=%s %s", self.pre, cueKin,
                            cuedSerder.said)
                logger.debug(f"event=\n{cuedSerder.pretty()}\n")

            elif cueKin in ("noticeBadCloneFN",):  # cue to notify of bad cloned first seen ordinal
                cuedSerder = cue["serder"]
                fn = cue["fn"]
                firner = cue["firner"]
                dater = cue["dater"]
                logger.error("%s got cue: kin=%s %s mismatch fn=%s expected=%s at %s",
                             self.pre, cueKin, cuedSerder.said, fn, firner.sn,
                             dater.dts)
                logger.debug(f"event=\n{cuedSerder.pretty()}\n")

            # ToDo XXXX cue for kin = "approveDelegation" own is delegator
            # ToDo XXXX cue for kin = "psUnescrow"
            # ToDo XXXX cue for kin=""remoteMemberedSig""

            elif cueKin in ("keyStateSaved",):  # cue to notify that key state has been saved
                ksn = cue["ksn"]
                logger.info("%s got cue: kin=%s for aid=%s at sn=%s",
                            self.pre, cueKin, ksn.get("i"), ksn.get("s"))

            elif cueKin in ("stream",):  # cue to notify of a query stream request
                cuedSerder = cue["serder"]
                pre = cue["pre"]
                src = cue["src"]
                topics = cue["topics"]
                logger.info("%s got cue: kin=%s for pre=%s src=%s topics=%s",
                            self.pre, cueKin, pre, src, topics)
                logger.debug(f"event=\n{cuedSerder.pretty()}\n")

            elif cueKin in ("invalid",):  # cue to notify of an invalid query message
                cuedSerder = cue["serder"]
                logger.error("%s got cue: kin=%s %s",
                             self.pre, cueKin, cuedSerder.said)
                logger.debug(f"event=\n{cuedSerder.pretty()}\n")

    def witnesser(self):
        return True


class Hab(BaseHab):
    """Local habitat for a given identifier controller.

    Provides the local resource environment (hab or habitat) for a controller,
    including dependency injection of the database, keystore, configuration
    file, Kevery, and key store Manager.

    Attributes:
        ks (keeping.Keeper): LMDB key store. (Injected)
        db (basing.Baser): LMDB database for KEL etc. (Injected)
        cf (configing.Configer): Configuration file instance. (Injected)
        mgr (keeping.Manager): Creates and rotates keys in the key store. (Injected)
        rtr (routing.Router): Routes reply ``rpy`` messages. (Injected)
        rvy (routing.Revery): Factory that processes reply ``rpy`` messages. (Injected)
        kvy (eventing.Kevery): Factory for local processing of local event messages. (Injected)
        psr (parsing.Parser): Parses local messages for ``.kvy`` and ``.rvy``. (Injected)
        name (str): Alias of the controller.
        pre (str): qb64 prefix of the own local controller, or ``None`` if new.
        temp (bool): ``True`` means testing — uses weak level when salty algo
            for stretching in key creation for incept and rotate of keys for
            this hab.pre.
        inited (bool): ``True`` means fully initialized with respect to
            databases; ``False`` means not yet fully initialized.
        delpre (str or None): Delegator prefix if any, else ``None``.
        kevers (dict): Kever instances from KELs in the local db, keyed by
            qb64 prefix. Read-through cache of states for KELs in
            ``db.states``. (Read-only property)
        iserder (serdering.SerderKERI): Own inception event. (Read-only property)
        prefixes (oset.OrderedSet): Local prefixes for ``.db``. (Read-only property)
        accepted (bool): ``True`` means accepted into the local KEL,
            ``False`` otherwise. (Read-only property)
    """

    def __init__(self, **kwa):
        super(Hab, self).__init__(**kwa)

    def make(self, *, secrecies=None, iridx=0, code=MtrDex.Blake3_256, dcode=MtrDex.Blake3_256,
             icode=MtrDex.Ed25519_Seed, transferable=True, isith=None, icount=1, nsith=None, ncount=None,
             toad=None, wits=None, delpre=None, estOnly=False, DnD=False, hidden=False, data=None, algo=None,
             salt=None, tier=None):
        """Finish setting up or making this Hab from parameters, including inception.

        Assumes injected dependencies have already been set up. When
        ``secrecies`` are provided the key manager replays pre-loaded key
        pairs; otherwise it generates new keys via ``mgr.incept``.

        After key material is prepared the inception event is built,
        persisted to the habitat record store, and processed by the local
        Kevery.  ``MissingSignatureError`` is silently swallowed during
        delegated-identifier initialisation.

        Args:
            secrecies (list or None): List of secret seeds to pre-load key
                pairs. When provided, key pairs are replayed rather than
                generated. Defaults to ``None``.
            iridx (int): Initial rotation index used after ingestion of
                ``secrecies``. Defaults to ``0``.
            code (str): Prefix derivation code. Defaults to
                ``MtrDex.Blake3_256``.
            dcode (str): Next-key derivation code. Defaults to
                ``MtrDex.Blake3_256``.
            icode (str): Signing key derivation code. Defaults to
                ``MtrDex.Ed25519_Seed``.
            transferable (bool): ``True`` means the prefix is transferable
                (default). ``False`` means non-transferable; forces
                ``ncount=0``, ``nsith='0'``, and ``code=MtrDex.Ed25519N``.
            isith (int, str, list, or None): Incepting signing threshold as an
                int, hex str, or weighted list. Computed from ``verfers`` when
                ``None``.
            icount (int): Number of incepting signing keys. Defaults to ``1``.
            nsith (int, str, list, or None): Next signing threshold as an int,
                hex str, or weighted list. Defaults to ``isith`` when ``None``.
            ncount (int or None): Number of next (pre-rotated) keys. Defaults
                to ``icount`` when ``None``.
            toad (int, str, or None): Witness threshold as an int or hex str.
                Computed from the number of witnesses when ``None``.
            wits (list or None): qb64 prefixes of witnesses, if any.
            delpre (str or None): qb64 delegator identifier prefix, if any.
            estOnly (bool): ``True`` adds ``TraitDex.EstOnly``, restricting
                the KEL to establishment events only. Defaults to ``False``.
            DnD (bool): ``True`` adds ``TraitDex.DnD``, disallowing delegated
                identifiers from this identifier. Defaults to ``False``.
            hidden (bool): When ``True`` the Hab is not saved to the habitat
                record store and its prefix is not added to ``self.prefixes``.
                Defaults to ``False``.
            data (list or None): Seal dicts to embed in the inception event.
            algo (str or None): Key-creation algorithm code used by the key
                manager when generating new keys.
            salt (str or None): qb64 salt for randomisation when the salty
                algorithm is used.
            tier (str or None): Security-criticality tier code used with the
                salty algorithm.

        Raises:
            ClosedError: If the key store, database, or config file is not
                open.
            ConfigurationError: If inception event processing fails for any
                reason other than a missing signature.
        """
        if not (self.ks.opened and self.db.opened and self.cf.opened):
            raise ClosedError("Attempt to make Hab with unopened "
                                     "resources.")
        if nsith is None:
            nsith = isith
        if ncount is None:
            ncount = icount
        if not transferable:
            ncount = 0  # next count
            nsith = '0'
            code = MtrDex.Ed25519N

        stem = self.name if self.ns is None else f"{self.ns}{self.name}"
        if secrecies:  # replay
            ipre, _ = self.mgr.ingest(secrecies,
                                      iridx=iridx,
                                      ncount=ncount,
                                      stem=stem,
                                      transferable=transferable,
                                      temp=self.temp)
            verfers, digers = self.mgr.replay(pre=ipre, advance=False)

        else:  # use defaults
            verfers, digers = self.mgr.incept(icount=icount,
                                              icode=icode,
                                              ncount=ncount,
                                              stem=stem,
                                              transferable=transferable,
                                              dcode=dcode,
                                              algo=algo,
                                              salt=salt,
                                              tier=tier,
                                              temp=self.temp)

        serder = super(Hab, self).make(isith=isith,
                                       verfers=verfers,
                                       nsith=nsith,
                                       digers=digers,
                                       code=code,
                                       toad=toad,
                                       wits=wits,
                                       estOnly=estOnly,
                                       DnD=DnD,
                                       delpre=delpre,
                                       data=data)

        self.pre = serder.ked["i"]  # new pre

        opre = verfers[0].qb64  # default zeroth original pre from key store
        self.mgr.move(old=opre, new=self.pre)  # move to incept event pre

        # may want db method that updates .habs. and .prefixes together
        habord = HabitatRecord(hid=self.pre, name=self.name, domain=self.ns)

        # must add self.pre to self.prefixes before calling processEvent so that
        # Kever.locallyOwned or Kever.locallyDelegated or Kever.locallyWitnessed
        # evaluates correctly when processing own inception event.
        if not hidden:
            self.save(habord)
            self.prefixes.add(self.pre)

        # sign handles group hab with .mhab case
        sigers = self.sign(ser=serder.raw, verfers=verfers)

        # during delegation initialization of a habitat we ignore the MissingDelegationError and
        # MissingSignatureError
        try:
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except MissingSignatureError:
            pass
        except Exception as ex:
            raise ConfigurationError("Improper Habitat inception for "
                                            "pre={} {}".format(self.pre, ex))

        # read in self.cf config file and process any oobis or endpoints
        self.reconfigure()  # should we do this for new Habs not loaded from db

        self.inited = True

    @property
    def algo(self):
        pp = self.ks.prms.get(self.pre)
        return pp.algo

    def rotate(self, *, isith=None, nsith=None, ncount=None, toad=None, cuts=None, adds=None,
               data=None, **kwargs):
        """Perform a rotation operation and register it in the database.

        Advances the key state by replaying the pre-committed next keys
        (``mgr.replay``) or, when no pre-committed keys exist, generating a
        fresh set (``mgr.rotate``).  Key store state is rolled back
        automatically if the rotation event fails validation, keeping the key
        store and KEL in sync (see issue #819).  Stale private keys from the
        previous signing set are erased only after successful validation.

        Args:
            isith (int, str, list, or None): Current signing threshold as an
                int, hex str, or weighted list. Defaults to the prior next
                threshold when ``None``.
            nsith (int, str, list, or None): Next signing threshold as an int,
                hex str, or weighted list. Defaults to ``isith`` when ``None``.
            ncount (int or None): Number of next (pre-rotated) keys. Defaults
                to the length of the prior next digers when ``None``.
            toad (int, str, or None): Witness threshold after cuts and adds, as
                an int or hex str.
            cuts (list or None): qb64 prefixes of witnesses to remove.
            adds (list or None): qb64 prefixes of witnesses to add.
            data (list or None): Seal dicts to embed in the rotation event.

        Returns:
            bytearray: Rotation message with attached signatures.

        Raises:
            Exception: Re-raises any exception raised by
                ``BaseHab.rotate`` after rolling back key store state.
        """
        # recall that kever.pre == self.pre
        kever = self.kever  # before rotation kever is prior next

        if ncount is None:
            ncount = len(kever.ndigers)  # use len of prior next digers as default

        # Save pre-rotation key state so we can rollback if event validation
        # fails. Both mgr.replay() and mgr.rotate() advance and persist key
        # state before the rotation event is validated by BaseHab.rotate().
        # Without rollback, a failed rotation leaves the key store out of
        # sync with the KEL (issue #819).
        ps_before = self.mgr.ks.sits.get(self.pre)

        try:
            verfers, digers = self.mgr.replay(pre=self.pre, erase=False)
        except IndexError:  # old next is new current
            verfers, digers = self.mgr.rotate(pre=self.pre,
                                              ncount=ncount,
                                              temp=self.temp,
                                              erase=False)

        try:
            msg = super(Hab, self).rotate(verfers=verfers, digers=digers,
                                          isith=isith,
                                          nsith=nsith,
                                          toad=toad,
                                          cuts=cuts,
                                          adds=adds,
                                          data=data)
        except Exception:
            # Rotation event validation failed. Rollback key state to
            # pre-rotation snapshot so KEL and key store stay in sync.
            self.mgr.ks.sits.pin(self.pre, val=ps_before)
            raise

        # Event validated successfully. Now safe to erase old stale
        # private keys that were preserved during the key advancement.
        if ps_before.old.pubs:
            for pub in ps_before.old.pubs:
                self.mgr.ks.pris.rem(pub)

        return msg


class SignifyHab(BaseHab):
    """Remote-signer habitat for a given identifier controller.

    Provides the local resource environment (hab or habitat) for a controller
    whose private keys are held by a remote signer (Signify agent), rather
    than locally.  Inception and rotation events are supplied to ``make`` and
    ``rotate`` as pre-built, pre-signed serders; this class never generates or
    holds private key material, and its ``sign`` method always raises
    ``KeriError``.

    Attributes:
        ks (keeping.Keeper): LMDB key store. (Injected)
        db (basing.Baser): LMDB database for KEL etc. (Injected)
        cf (configing.Configer): Configuration file instance. (Injected)
        mgr (keeping.Manager): Creates and rotates keys in the key store. (Injected)
        rtr (routing.Router): Routes reply ``rpy`` messages. (Injected)
        rvy (routing.Revery): Factory that processes reply ``rpy`` messages. (Injected)
        kvy (eventing.Kevery): Factory for local processing of local event messages. (Injected)
        psr (parsing.Parser): Parses local messages for ``.kvy`` and ``.rvy``. (Injected)
        name (str): Alias of the controller.
        pre (str): qb64 prefix of the own local controller, or ``None`` if new.
        temp (bool): ``True`` means testing — uses weak level when salty algo
            for stretching in key creation for incept and rotate of keys for
            this hab.pre.
        inited (bool): ``True`` means fully initialized with respect to
            databases; ``False`` means not yet fully initialized.
        delpre (str or None): Delegator prefix if any, else ``None``.
    """

    def __init__(self, **kwa):
        super(SignifyHab, self).__init__(**kwa)

    def make(self, *, serder, sigers, **kwargs):
        """Finish setting up this SignifyHab from a pre-built inception event.

        Registers the prefix, processes the inception event through the local
        Kevery, persists the habitat record, and marks the hab as initialised.

        Args:
            serder (SerderKERI): Pre-built inception event serder. The prefix
                ``serder.ked["i"]`` is assigned to ``self.pre``.
            sigers (list[Siger]): Siger instances carrying the remote
                agent's signatures over ``serder.raw``.
            **kwargs: Absorbed for API compatibility; not used.
        """
        self.pre = serder.ked["i"]  # new pre
        self.prefixes.add(self.pre)

        self.processEvent(serder, sigers)

        habord = HabitatRecord(hid=self.pre, sid=self.pre, name=self.name, domain=self.ns)
        self.save(habord)

        self.inited = True

    def sign(self, ser, verfers=None, indexed=True, indices=None, ondices=None, **kwa):
        """Signing is not supported for SignifyHab.

        Private keys are held by the remote Signify agent, so local signing is
        intentionally disabled.

        Args:
            ser (bytes): Serialization to sign.
            verfers (list or None): Ignored.
            indexed (bool): Ignored.
            indices (list or None): Ignored.
            ondices (list or None): Ignored.
            **kwa: Ignored.

        Raises:
            KeriError: Always because local signing is not permitted for this hab type.
        """
        raise KeriError("Signify hab does not support local signing")

    def rotate(self, *, serder=None, sigers=None, **kwargs):
        """Perform a rotation operation from a pre-built, pre-signed event.

        Packages the provided serder and sigers into a message and processes
        it through the local Kevery to update key state.

        Args:
            serder (SerderKERI): Pre-built rotation event serder.
            sigers (list[Siger]): Siger instances carrying the remote
                agent's signatures over ``serder.raw``.
            **kwargs: Absorbed for API compatibility; not used.

        Returns:
            bytearray: Rotation message with attached signatures.
        """
        msg = messagize(serder, sigers=sigers)
        self.processEvent(serder, sigers)
        return msg

    def interact(self, *, serder=None, sigers=None, **kwargs):
        """Perform an interaction operation from a pre-built, pre-signed event.

        Packages the provided serder and sigers into a message and processes
        it through the local Kevery to update key state.

        Args:
            serder (SerderKERI): Pre-built interaction event serder.
            sigers (list[Siger]): Siger instances carrying the remote
                agent's signatures over ``serder.raw``.
            **kwargs: Absorbed for API compatibility; not used.

        Returns:
            bytearray: Interaction message with attached signatures.
        """
        msg = messagize(serder, sigers=sigers)
        self.processEvent(serder, sigers)
        return msg

    def exchange(self, serder, seal=None, sigers=None, save=False):
        """Build and optionally persist a signed ``exn`` exchange message.

        Assembles a peer-to-peer exchange message from the pre-built serder
        and provided signatures.  When ``save`` is ``True`` a local copy is
        parsed into the database for record keeping.

        Args:
            serder (SerderKERI): Pre-built exchange event serder.
            seal (Seal or None): Optional seal to attach to the message.
            sigers (list or None): Siger instances carrying signatures
                over ``serder.raw``.
            save (bool): When ``True``, parse a copy of the assembled message
                into the local database. Defaults to ``False``.

        Returns:
            bytearray: Exchange message with count code and attached
            signatures.
        """
        # sign serder event
        msg = messagize(serder=serder, sigers=sigers, seal=seal)

        if save:
            self.psr.parseOne(ims=bytearray(msg))  # process local copy into db

        return msg

    def processEvent(self, serder, sigers):
        """Process an event through the local Kevery, re-raising all exceptions.

        Unlike ``GroupHab.processEvent``, this method does **not** swallow
        ``MissingSignatureError``; any exception from the Kevery is wrapped
        in a ``ConfigurationError`` and re-raised.

        Args:
            serder (SerderKERI): Event serder to process.
            sigers (list): Signature instances over
                ``serder.raw``.

        Raises:
            ConfigurationError: If the Kevery raises any exception during
                event processing.
        """

        try:
            # verify event, update kever state, and escrow if group
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except Exception:
            raise ConfigurationError(f"Improper Habitat event type={serder.ked['t']} for "
                                            f"pre={self.pre}.")

    def replyEndRole(self, cid, role=None, eids=None, scheme=""):
        """Build a reply message stream for endpoint role authorisations.

        Assembles a ``rpy`` message stream containing the KEL replay for
        ``cid`` plus any authorised endpoint role records and location scheme
        records relevant to the requested role and scheme filters.  Uses a
        promiscuous discovery model — future versions may restrict discovery
        via an identity constraint graph.

        The returned stream content depends on the combination of arguments:

        * ``cid`` only — end authz for all eids in all roles, loc URLs for
          all schemes at each eid (optionally restricted to ``eids``).
        * ``cid`` + ``scheme`` — end authz for all eids in all roles, loc URL
          for ``scheme`` at each eid (optionally restricted to ``eids``).
        * ``cid`` + ``role`` — end authz for all eids in ``role``, loc URLs
          for all schemes at each eid (optionally restricted to ``eids``).
        * ``cid`` + ``role`` + ``scheme`` — end authz for all eids in
          ``role``, loc URL for ``scheme`` at each eid (optionally restricted
          to ``eids``).

        When ``role`` is ``Roles.witness`` and this hab is itself one of
        ``cid``'s witnesses, the KEL replay is used as the authorisation
        instead of explicit end-role records.

        Args:
            cid (str): qb64 identifier prefix of the controller whose
                endpoint authorisations are being requested.
            role (str or None): Authorised role to filter by. ``None`` means
                all roles.
            eids (list or None): When provided, restricts returned records to
                only the endpoint identifiers listed here.
            scheme (str): URL scheme to filter location records by. An empty
                string (default) means all schemes.

        Returns:
            bytearray: Concatenated reply message stream containing KEL
            replay, location scheme records, and end-role records.
        """
        msgs = bytearray()

        if eids is None:
            eids = []

        # introduce yourself, please
        msgs.extend(self.replay(cid))

        if role == Roles.witness:
            if kever := self.kevers[cid] if cid in self.kevers else None:
                witness = self.pre in kever.wits  # see if we are cid's witness

                # latest key state for cid
                for eid in kever.wits:
                    if not eids or eid in eids:
                        msgs.extend(self.loadLocScheme(eid=eid, scheme=scheme))
                        if not witness:  # we are not witness, send auth records
                            msgs.extend(self.makeEndRole(eid=eid, role=role))
                if witness:  # we are witness, set KEL as authz
                    msgs.extend(self.replay(cid))

        for (_, erole, eid), end in self.db.ends.getTopItemIter(keys=(cid,)):
            if (end.enabled or end.allowed) and (not role or role == erole) and (not eids or eid in eids):
                msgs.extend(self.replay(eid))
                msgs.extend(self.loadLocScheme(eid=eid, scheme=scheme))
                msgs.extend(self.loadEndRole(cid=cid, eid=eid, role=erole))

        return msgs


class SignifyGroupHab(SignifyHab):
    """Remote-signer group (multisig) habitat.

    Extends ``SignifyHab`` to support multisig group identifiers whose private
    keys are held by a remote Signify agent.  Tracks the group signing member
    aids (``smids``) and rotating member aids (``rmids``) alongside the local
    participant member hab (``mhab``).

    Attributes:
        mhab (SignifyHab): The local participant member hab for this group.
        smids (list[str]): qb64 prefixes of current signing members of the
            group.
        rmids (list[str]): qb64 prefixes of rotating members of the group.
            Defaults to ``smids`` when not supplied.
    """

    def __init__(self, smids, mhab=None, rmids=None, **kwa):
        self.mhab = mhab
        self.smids = smids  # group signing member aids in this group hab
        self.rmids = rmids or smids # group rotating member aids in this group hab

        super(SignifyGroupHab, self).__init__(**kwa)

    def make(self, *, serder, sigers, **kwargs):
        """Finish setting up this SignifyGroupHab from a pre-built inception event.

        Registers the group prefix, processes the inception event, persists the
        habitat record (including group member metadata), and marks the hab as
        initialised.

        Args:
            serder (SerderKERI): Pre-built inception event serder. The prefix
                ``serder.ked["i"]`` is assigned to ``self.pre``.
            sigers (list[Siger]): Siger instances carrying the remote
                agent's signatures over ``serder.raw``.
            **kwargs: Absorbed for API compatibility; not used.
        """
        self.pre = serder.ked["i"]  # new pre
        self.prefixes.add(self.pre)

        self.processEvent(serder, sigers)

        habord = HabitatRecord(hid=self.pre, mid=self.mhab.pre, smids=self.smids, rmids=self.rmids,
                                      sid=self.pre, name=self.name, domain=self.ns)
        self.save(habord)

        self.inited = True

    def processEvent(self, serder, sigers):
        """Process an event through the local Kevery, tolerating missing signatures.

        ``MissingSignatureError`` is silently swallowed so that multisig events
        can be created and stored with only a single local member's signature,
        pending collection of the remaining co-signers' contributions.

        Args:
            serder (SerderKERI): Event serder to process.
            sigers (list): Signature instances over
                ``serder.raw``.

        Raises:
            ValidationError: If the Kevery raises any exception other than
                ``MissingSignatureError``.
        """

        try:
            # verify event, update kever state, and escrow if group
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except MissingSignatureError:
            pass
        except Exception:
            raise ValidationError(f"Improper Habitat event type={serder.ked['t']} for "
                                         f"pre={self.pre}.")

    def rotate(self, *, smids=None, rmids=None, serder=None, sigers=None, **kwargs):
        """Perform a rotation operation and update group member lists.

        Delegates the core rotation to ``SignifyHab.rotate``, then updates the
        ``smids`` and ``rmids`` on both the instance and the persisted
        ``HabitatRecord``.

        Args:
            smids (list or None): Updated qb64 prefixes of signing members
                after rotation.
            rmids (list or None): Updated qb64 prefixes of rotating members
                after rotation.
            serder (SerderKERI): Pre-built rotation event serder.
            sigers (list[Siger]): Siger instances carrying the remote
                agent's signatures over ``serder.raw``.
            **kwargs: Absorbed for API compatibility; not used.

        Raises:
            ValidationError: If the habitat record for ``self.pre`` does not
                exist in the database.
        """

        if (habord := self.db.habs.get(keys=(self.pre,))) is None:
            raise ValidationError(f"Missing HabitatRecord for pre={self.pre}")

        super(SignifyGroupHab, self).rotate(serder=serder, sigers=sigers, **kwargs)

        self.smids = smids
        self.rmids = rmids
        habord.smids = smids
        habord.rmids = rmids

        self.db.habs.pin(keys=(self.pre,), val=habord)


class GroupHab(BaseHab):
    """Local group (multisig) habitat for a given identifier controller.

    Provides the local resource environment (hab or habitat) for a multisig
    group controller, including dependency injection of the database, keystore,
    configuration file, Kevery, and key store Manager.

    Signing is performed through the local member hab (``mhab``) by walking
    its KEL to locate the correct contributed key material.  ``MissingSignatureError``
    is silently swallowed during inception and rotation processing so that group
    events can be created and stored with a single local member's signature
    while awaiting the remaining co-signers' contributions.

    Attributes:
        ks (keeping.Keeper): LMDB key store. (Injected)
        db (basing.Baser): LMDB database for KEL etc. (Injected)
        cf (configing.Configer): Configuration file instance. (Injected)
        mgr (keeping.Manager): Creates and rotates keys in the key store. (Injected)
        rtr (routing.Router): Routes reply ``rpy`` messages. (Injected)
        rvy (routing.Revery): Factory that processes reply ``rpy`` messages. (Injected)
        kvy (eventing.Kevery): Factory for local processing of local event messages. (Injected)
        psr (parsing.Parser): Parses local messages for ``.kvy`` and ``.rvy``. (Injected)
        name (str): Alias of the controller.
        pre (str): qb64 prefix of the own local controller, or ``None`` if new.
        mhab (Hab or None): Local participant member hab of this group hab.
        smids (list or None): qb64 prefixes of current signing members of
            the group.
        rmids (list or None): qb64 prefixes of rotating members of the
            group. Defaults to a copy of ``smids`` when not supplied.
        temp (bool): ``True`` means testing — uses weak level when salty algo
            for stretching in key creation for incept and rotate of keys for
            this hab.pre.
        inited (bool): ``True`` means fully initialized with respect to
            databases; ``False`` means not yet fully initialized.
        delpre (str or None): Delegator prefix if any, else ``None``.
        kevers (dict): Kever instances from KELs in the local db, keyed by
            qb64 prefix. Read-through cache of states for KELs in
            ``db.states``. (Read-only property)
        iserder (serdering.SerderKERI): Own inception event. (Read-only property)
        prefixes (oset.OrderedSet): Local prefixes for ``.db``. (Read-only property)
        accepted (bool): ``True`` means accepted into the local KEL,
            ``False`` otherwise. (Read-only property)
    """

    def __init__(self, smids, mhab=None, rmids=None, **kwa):
        """Initialise a GroupHab instance.

        Args:
            smids (list[str]): qb64 prefixes of the current signing members of
                the multisig group.
            mhab (Hab or None): Local participant member hab. The ``mhab.pre``
                aid may appear in ``smids``, ``rmids``, or both.
            rmids (list or None): qb64 prefixes of the rotating members of
                the multisig group. Defaults to ``smids`` when ``None``.
            **kwa: Keyword arguments forwarded to ``BaseHab.__init__``,
                including all injected dependencies (``ks``, ``db``, ``cf``,
                ``mgr``, ``rtr``, ``rvy``, ``kvy``, ``psr``), ``name``,
                ``pre``, and ``temp``.
        """
        self.mhab = mhab  # local participant Hab of this group hab
        self.smids = smids  # group signing member aids in this group hab
        self.rmids = rmids or smids  # group rotating member aids in this group hab

        super(GroupHab, self).__init__(**kwa)

    def make(self, *, code=MtrDex.Blake3_256, transferable=True, isith=None, nsith=None,
             toad=None, wits=None, delpre=None, estOnly=False, DnD=False,
             merfers, migers=None, data=None):
        """Finish setting up or making this GroupHab from parameters, including inception.

        Assembles the group inception event from the collected member key
        material (``merfers``, ``migers``), signs it via the local member hab
        (``mhab``), persists the habitat record, and processes the event
        through the local Kevery.  ``MissingSignatureError`` is silently
        swallowed during delegated-identifier initialisation.

        Assumes injected dependencies have already been set up.

        Args:
            code (str): Prefix derivation code. Defaults to
                ``MtrDex.Blake3_256``.
            transferable (bool): ``True`` means the prefix is transferable
                (default). ``False`` forces ``nsith='0'`` and
                ``code=MtrDex.Ed25519N``.
            isith (int, str, list, or None): Incepting signing threshold as an
                int, hex str, or weighted list. Computed from ``verfers`` when
                ``None``.
            nsith (int, str, list, or None): Next signing threshold as an int,
                hex str, or weighted list. Defaults to ``isith`` when ``None``.
            toad (int, str, or None): Witness threshold as an int or hex str.
                Computed from the number of witnesses when ``None``.
            wits (list or None): qb64 prefixes of witnesses, if any.
            delpre (str or None): qb64 delegator identifier prefix, if any.
            estOnly (bool): ``True`` adds ``TraitDex.EstOnly``, restricting
                the KEL to establishment events only. Defaults to ``False``.
            DnD (bool): ``True`` adds ``TraitDex.DnD``, disallowing delegated
                identifiers from this identifier. Defaults to ``False``.
            merfers (list[Verfer]): ``Verfer`` instances of the public signing
                keys contributed by each multisig group member. Exactly one
                key per member; the zeroth element of each member's key list
                by convention.
            migers (list or None): ``Diger`` instances of the public
                next-key digests contributed by each multisig group member.
                ``None`` means no pre-rotation material is included.
            data (list or None): Seal dicts to embed in the inception event.

        Raises:
            ClosedError: If the key store, database, or config file is not
                open.
            ConfigurationError: If inception event processing fails for any
                reason other than a missing signature.
        """
        if not (self.ks.opened and self.db.opened and self.cf.opened):
            raise ClosedError("Attempt to make Hab with unopened "
                                     "resources.")
        if nsith is None:
            nsith = isith
        if not transferable:
            nsith = '0'
            code = MtrDex.Ed25519N

        verfers = merfers
        digers = migers

        serder = super(GroupHab, self).make(isith=isith,
                                            verfers=verfers,
                                            nsith=nsith,
                                            digers=digers,
                                            code=code,
                                            toad=toad,
                                            wits=wits,
                                            estOnly=estOnly,
                                            DnD=DnD,
                                            delpre=delpre,
                                            data=data)

        self.pre = serder.ked["i"]  # new pre

        # sign handles group hab with .mhab case
        sigers = self.sign(ser=serder.raw, verfers=verfers)

        habord = HabitatRecord(hid=self.pre,
                                      mid=self.mhab.pre,
                                      name=self.name,
                                      domain=self.ns,
                                      smids=self.smids,
                                      rmids=self.rmids)
        self.save(habord)
        self.prefixes.add(self.pre)

        # during delegation initialization of a habitat we ignore the MissingDelegationError and
        # MissingSignatureError
        try:
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except MissingSignatureError:
            pass
        except Exception as ex:
            raise ConfigurationError("Improper Habitat inception for "
                                            "pre={} {}".format(self.pre, ex))


        self.inited = True

    def rotate(self, smids=None, rmids=None, serder=None, **kwargs):
        """Perform a rotation operation and update group member lists.

        When ``serder`` is ``None``, delegates entirely to
        ``BaseHab.rotate(**kwargs)`` for a locally-driven rotation.  When a
        pre-built rotation ``serder`` is provided, the local member hab signs
        it, the result is processed through the local Kevery, and the
        ``smids``/``rmids`` member lists are updated on both the instance and
        the persisted ``HabitatRecord``.

        Args:
            smids (list or None): Updated qb64 prefixes of signing members
                after rotation.
            rmids (list or None): Updated qb64 prefixes of rotating members
                after rotation.
            serder (SerderKERI or None): Pre-built rotation event serder.  When
                ``None`` a rotation event is generated by ``BaseHab.rotate``.
            **kwargs: Keyword arguments forwarded to ``BaseHab.rotate`` when
                ``serder`` is ``None``.

        Returns:
            bytearray: Rotation message with attached signatures.

        Raises:
            ValidationError: If the habitat record for ``self.pre`` does not
                exist in the database, or if rotation event processing fails
                for any reason other than a missing signature.
        """

        if serder is None:
            return super(GroupHab, self).rotate(**kwargs)

        if (habord := self.db.habs.get(keys=(self.pre,))) is None:
            raise ValidationError(f"Missing HabitatRecord for pre={self.pre}")

        # sign handles group hab with .mhab case
        sigers = self.sign(ser=serder.raw, verfers=serder.verfers, rotated=True)

        # update own key event verifier state
        msg = messagize(serder, sigers=sigers)

        try:
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except MissingSignatureError:
            pass
        except Exception as ex:
            raise ValidationError("Improper Habitat rotation for "
                                         "pre={self.pre}.") from ex

        self.smids = smids
        self.rmids = rmids
        habord.smids = smids
        habord.rmids = rmids
        self.db.habs.pin(keys=(self.pre,), val=habord)

        return msg

    def sign(self, ser, verfers=None, indexed=True, rotated=False, indices=None, ondices=None):
        """Sign a serialisation using the local member hab's key material.

        Walks the member hab's (``mhab``) KEL to locate the latest event at
        which ``mhab`` contributed signing key material to the group, then
        delegates to ``mhab.sign`` with the appropriate current index
        (``csi``) and, for rotation events, the optional prior-next other
        index (``pni``).

        By convention the contributed member key is always the zeroth element
        of the member's signing key list, and the contributed member next-key
        digest is always the zeroth element of the member's next-key digest
        list.

        Args:
            ser (bytes): Serialisation to sign.
            verfers (list or None): ``Verfer`` instances representing
                the group's current signing keys. ``None`` means use
                ``self.kever.verfers``.
            indexed (bool): ``True`` means return indexed ``Siger`` instances;
                ``False`` means return unindexed ``Cigar`` instances.
                Defaults to ``True``.
            rotated (bool): When ``True``, compute dual-indexed signatures —
                the current signing index (``csi``) and the prior-next other
                index (``pni``) — for use in a rotation event.  When ``False``
                (default), only the current signing index is used and ``pni``
                is set to ``None``.
            indices (list or None): Explicit current signing indices.
                Passed through to ``Manager.sign``; computed automatically
                when ``None``.
            ondices (list or None): Explicit prior-next other
                indices.  Passed through to ``Manager.sign``; computed
                automatically when ``None``.

        Returns:
            list[Siger] or list[Cigar]: Signature instances over ``ser``.

        Raises:
            ValueError: If ``mhab`` did not contribute to the group event
                identified by ``verfers``.
        """
        if verfers is None:
            verfers = self.kever.verfers  # when group these provide group signing keys

        # contributed member verfer from .mhab KEL.
        # Convention is to walk KEL to find correct contributed key if any.
        # Contributed keys MUSt always be zeroth element of member key list
        # and or member next key digests list.
        # first dig of mhab's prior nexter.digs.

        # walk member kel to find event if event where member contributed to
        # group est event from which verfers is taken
        if (result := self.mhab.kever.fetchLatestContribTo(verfers=verfers)) is None:
            raise ValueError(f"Member hab={self.mhab.pre} not a participant in "
                             f"event for this group hab={self.pre}.")

        sn, csi, merfer = result  # unpack result

        # the rotated flag may now be obsolete since fixing the Kever validation
        # logic to correctly chack both of the dual indices
        if rotated:  # rotation so uses the other index from dual indices
            # Either the verfer key or both the verfer key and prior dig
            # might be participants in signature on group hab's rotation event.
            # Each prior dig  must also be exposed as a participant
            # from current (after rotation) key list.
            # If mhab.kever.verfer[0] key is in group's new verfers (after rot)
            # then mhab participates in group as new key at index csi.
            # If in addition mhab prior dig at nexter.digs[0] is in group's
            # kever.digers (which will be prior next for group after rotation)
            # then mhab participates as group prior next at index pni.
            # else pni is None which means mhab only participates as new key.
            # get nexter of .mhab's prior Next est event
            migers = self.mhab.kever.fetchPriorDigers(sn=sn - 1)
            if migers:  # not  None or not empty
                mig = migers[0].qb64  # always use first prior dig of mhab
                digs = [diger.qb64 for diger in self.kever.ndigers]  # group habs prior digs
                try:
                    pni = digs.index(mig)  # find mhab dig index in group hab digs
                except ValueError:  # not found
                    pni = None  # default not participant
            else:
                pni = None  # default not participant

        else:  # not a rotation so ignores other index of dual index
            # pni = csi  # backwards compatible is both same
            # in the future may want to fix Kever validation logic so that
            pni = None  # should also work

        return (self.mhab.sign(ser=ser,
                               verfers=[merfer],
                               indexed=indexed,
                               indices=[csi],
                               ondices=[pni]))

    def witness(self, serder):
        """Group habs cannot act as witnesses.

        Args:
            serder (SerderKERI): Ignored.

        Raises:
            ValueError: Always — group habs are not valid witnesses and cannot
                provide witness receipts.
        """
        raise ValueError("Attempt to witness by group hab ={self.pre}.")

    def query(self, pre, src, query=None, **kwa):
        """Create, sign, and return a signed ``qry`` query message.

        Builds a query event for ``pre`` directed at attester ``src``, then
        endorses it through the local member hab (``mhab``) using the last
        event in ``mhab``'s KEL.

        Args:
            pre (str): qb64 identifier prefix being queried for.
            src (str): qb64 identifier prefix of the attester being queried.
            query (dict or None): Additional query modifiers to include in the
                ``q`` field. Defaults to an empty dict when ``None``.
            **kwa: Keyword arguments forwarded to ``queryEvent``.

        Returns:
            bytearray: Signed query message endorsed by ``mhab``.
        """

        query = query if query is not None else dict()
        query['i'] = pre
        query["src"] = src
        serder = queryEvent(query=query, **kwa)

        return self.mhab.endorse(serder, last=True)


    def witnesser(self):
        """Return whether this member hab holds the lowest-index signing key in the group.

        The member holding the lowest signing index among all signatures currently
        recorded in the database is elected by convention to perform coordination
        duties on behalf of the group, such as submitting delegation and witnessing
        requests.

        Returns:
            bool: ``True`` if ``mhab``'s zeroth verfer matches the group signing
            key at the lowest recorded signer index; ``False`` otherwise, including
            when no signatures are found in the database for the current event.
        """
        kever = self.kever
        keys = [verfer.qb64 for verfer in kever.verfers]
        sigers = self.db.sigs.get(keys=(self.pre, kever.serder.saidb))
        if not sigers:  # otherwise its a list of sigs
            return False

        windex = min([siger.index for siger in sigers])

        # True if Elected to perform delegation and witnessing
        return self.mhab.kever.verfers[0].qb64 == keys[windex]
