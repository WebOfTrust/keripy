# -*- encoding: utf-8 -*-
"""
KERI
keri.app.keeping module

Provides functionality for storing and retrieving cryptographic keys, events,
and certifiable data in a transactional store.

Terminology:
    salt:
        128-bit (16 character) random bytes used as root entropy to derive a
        seed or secret.

    private key:
        Same as seed or secret for a key pair.

    seed / secret:
        Crypto suite length-dependent random bytes used to derive key material.

    public key:
        Corresponding public key derived from the private key.

Example:
    Store certifiable data::

        .. code-block:: python

            txn.put(
                did.encode(),
                json.dumps(certifiable_data).encode("utf-8")
            )

    Retrieve certifiable data::

        .. code-block:: python

            raw_data = txn.get(did.encode())
            if raw_data is None:
                return None
            return json.loads(raw_data)

    Encode/decode key event data::

        .. code-block:: python

            ked = json.loads(raw[:size].decode("utf-8"))
            raw = json.dumps(
                ked, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
"""
import math
from collections import namedtuple, deque
from dataclasses import dataclass, asdict, field

import pysodium
from hio.base import doing

from ..kering import ClosedError, AuthError, DecryptError
from ..core import (Prefixer, Number, Diger, Tholder,
                    Cipher, Signer, Salter,
                    Encrypter, Decrypter, Tiers, MtrDex)
from ..db import (openLMDB, LMDBer, Suber,
                  CryptSignerSuber, CesrSuber,
                  CatCesrIoSetSuber, Komer)
from ..help import nowIso8601

Algoage = namedtuple("Algoage", 'randy salty group extern')
Algos = Algoage(randy='randy', salty='salty', group="group", extern="extern")  # randy is rerandomize, salty is use salt


@dataclass()
class PubLot:
    """A set of public keys with their position metadata and creation timestamp.

    Represents one ordered list of public keys associated with a single
    establishment event (inception or rotation), along with the indexes that
    describe where that set sits in the overall key sequence.

    Attributes:
        pubs (list[str]): Fully qualified Base64 public keys. Defaults to
            empty list.
        ridx (int): Rotation index of the establishment event that uses this
            public key set. The inception event has ``ridx == 0``.
        kidx (int): Key index of the first key in this set within the overall
            sequence of all public keys across all establishment events. For
            example, if each establishment event has 3 keys, the set at
            ``ridx == 2`` has ``kidx == 6``.
        dt (str): ISO 8601 datetime string recording when this key set was
            first created.
    """
    pubs: list = field(default_factory=list)  # list qb64 public keys.
    ridx: int = 0  # index of rotation (est event) that uses public key set
    kidx: int = 0  # index of key in sequence of public keys
    dt: str = ""  # datetime ISO8601 when key set created

    def __iter__(self):
        return iter(asdict(self))


@dataclass()
class PreSit:
    """The current public key situation for an identifier prefix.

    Tracks the three consecutive public key lots (old, new, nxt) that
    correspond to the previous, current, and next-rotation key sets for a
    prefix.  At any point in the rotation lifecycle:

    * ``old`` — the key set used before the most recent rotation.
    * ``new`` — the key set currently active for signing.
    * ``nxt`` — the pre-committed key set for the next rotation.

    Attributes:
        old (PubLot): The previous (now-rotated-away) public key lot.
        new (PubLot): The currently active public key lot.
        nxt (PubLot): The pre-committed next public key lot.
    """
    old: PubLot = field(default_factory=PubLot)  # previous publot
    new: PubLot = field(default_factory=PubLot)  # newly current publot
    nxt: PubLot = field(default_factory=PubLot)  # next public publot

    def __iter__(self):
        return iter(asdict(self))


@dataclass()
class PrePrm:
    """Key-creation parameters bound to an identifier prefix.

    Stores the algorithm and seed material needed to recreate or extend the
    key-pair sequence for a given prefix.

    Attributes:
        pidx (int): Prefix index that uniquely identifies this key-pair
            sequence within the keeper. Defaults to ``0``.
        algo (str): Key-creation algorithm code (e.g. ``Algos.salty`` or
            ``Algos.randy``). Defaults to ``Algos.salty``.
        salt (str): Fully qualified qb64 salt (or encrypted ciphertext of
            the salt) used by the salty algorithm. Empty string when not
            applicable.
        stem (str): Unique path stem combined with the salt to derive
            individual private keys. Empty string causes the salty creator
            to fall back to using the hex-encoded ``pidx`` as the stem.
        tier (str): Security tier that controls the hashing work factor
            during key stretching. Empty string defers to the keeper's root
            tier.
    """
    pidx: int = 0  # prefix index for this keypair sequence
    algo: str = Algos.salty  # salty default uses indices and salt to create new key pairs
    salt: str = ''  # empty salt  used for salty algo.
    stem: str = ''  # default unique path stem for salty algo
    tier: str = ''  # security tier for stretch index salty algo

    def __iter__(self):
        return iter(asdict(self))


@dataclass()
class PubSet:
    """An ordered list of public keys for a given prefix and rotation index.

    Used as the value type stored in the ``Keeper.pubs`` sub-database, keyed
    by ``riKey(pre, ridx)``.  Enables lookup of the full public key list for a
    specific establishment event during replay.

    Attributes:
        pubs (list[str]): Fully qualified qb64 public keys for a single
            establishment event. Defaults to empty list.
    """
    pubs: list = field(default_factory=list)  # list qb64 public keys.

    def __iter__(self):
        return iter(asdict(self))


def riKey(pre, ri):
    """Return a byte-string database key composed of a prefix and a rotation index.

    Concatenates the identifier prefix and the integer rotation index ``ri``
    with a ``'.'`` separator.  The rotation index is zero-padded to 32 hex
    characters so that lexicographic ordering of keys matches numeric ordering
    of rotation indexes.

    Args:
        pre (str | bytes): Fully qualified Base64 identifier prefix. A
            ``str`` is UTF-8 encoded to ``bytes`` automatically.
        ri (int): Rotation index of the establishment event. Inception has
            ``ri == 0``.

    Returns:
        bytes: Byte-string key of the form ``b'<pre>.<ri:032x>'``.
    """
    if hasattr(pre, "encode"):
        pre = pre.encode("utf-8")  # convert str to bytes
    return (b'%s.%032x' % (pre, ri))


def openKS(name="test", **kwa):
    """Return a context manager that opens a :class:`Keeper` key-store database.

    Thin wrapper around :func:`openLMDB` that passes :class:`Keeper` as the
    database class, so callers receive a temporary or persistent LMDB-backed
    key store without having to reference :class:`Keeper` directly.

    Args:
        name (str): Directory path name component used to differentiate
            multiple database instances. Defaults to ``"test"``.
        **kwa: Additional keyword arguments forwarded to :func:`openLMDB`
            (e.g. ``temp=True``).

    Returns:
        contextmanager: A context manager that yields an opened
        :class:`Keeper` instance and closes it on exit.
    """
    return openLMDB(cls=Keeper, name=name, **kwa)


class Keeper(LMDBer):
    """LMDB-backed key store for KERI key-pair management.

    Extends :class:`LMDBer` with named sub-databases tailored for storing
    cryptographic key pairs, encrypted secrets, prefix parameters, and public
    key situation state.  All private key material may optionally be encrypted
    at rest using an asymmetric encryption key derived from an authentication
    and encryption identifier (``aeid``).

    Attributes:
        gbls (Suber): Named sub-database of global parameters shared across
            all prefixes.  Keys are parameter labels (plain strings); values
            are parameter values.  Recognized labels:

            * ``"aeid"`` — fully qualified qb64 non-transferable identifier
              prefix whose associated key pair is used to authenticate the
              keeper and to asymmetrically encrypt secrets stored at rest.
              An empty value means no authentication or encryption is applied.
            * ``"pidx"`` — hex-encoded integer index of the next prefix
              key-pair sequence to be incepted.
            * ``"algo"`` — default root algorithm code for generating key
              pairs.
            * ``"salt"`` — root salt (plain or encrypted qb64) for generating
              key pairs.
            * ``"tier"`` — default root security tier for the root salt.

        pris (CryptSignerSuber): Named sub-database mapping each public key
            to its corresponding private key (signer).  Keys are fully
            qualified qb64 public keys; values are :class:`Signer` instances,
            stored encrypted when an ``aeid`` is configured.

        prxs (CesrSuber): Named sub-database of encrypted proxy ciphers,
            keyed by public key.  Values are :class:`Cipher` instances.

        nxts (CesrSuber): Named sub-database of encrypted next-key ciphers,
            keyed by public key.  Values are :class:`Cipher` instances.

        smids (CatCesrIoSetSuber): Named sub-database of signing member
            identifier sets, storing ``(Prefixer, Number)`` pairs as ordered
            duplicate sets.

        rmids (CatCesrIoSetSuber): Named sub-database of rotation member
            identifier sets, storing ``(Prefixer, Number)`` pairs as ordered
            duplicate sets.

        pres (CesrSuber): Named sub-database mapping the first public key of
            a key sequence (used as a temporary prefix) to the canonical
            identifier prefix once it is known.  Values are
            :class:`Prefixer` instances.

        prms (Komer): Named sub-database of key-creation parameters per
            prefix.  Keys are identifier prefixes (qb64); values are
            :class:`PrePrm` dataclass instances serialized as dicts::

                {
                    "pidx": <int>,
                    "algo": <str>,
                    "salt": <str>,
                    "stem": <str>,
                    "tier": <str>,
                }

        sits (Komer): Named sub-database of public key situation state per
            prefix.  Keys are identifier prefixes (qb64); values are
            :class:`PreSit` dataclass instances serialized as dicts::

                {
                    "old": {"pubs": [...], "ridx": <int>, "kidx": <int>, "dt": <str>},
                    "new": {"pubs": [...], "ridx": <int>, "kidx": <int>, "dt": <str>},
                    "nxt": {"pubs": [...], "ridx": <int>, "kidx": <int>, "dt": <str>},
                }

        pubs (Komer): Named sub-database of public key sets indexed by prefix
            and rotation index.  Keys are byte-string keys produced by
            :func:`riKey`; values are :class:`PubSet` dataclass instances.
            Enables ordered replay of all establishment events for a prefix.
    """
    TailDirPath = "keri/ks"
    AltTailDirPath = ".keri/ks"
    TempPrefix = "keri_ks_"
    MaxNamedDBs = 10

    def __init__(self, headDirPath=None, perm=None, reopen=False, **kwa):
        """Initialize the Keeper key store.

        Sets restrictive filesystem permissions by default (more restrictive
        than the :class:`LMDBer` base default) to protect private key
        material, then delegates to :meth:`LMDBer.__init__`.

        Args:
            headDirPath (str | None): Override for the head directory path of
                the LMDB environment.  ``None`` uses the class-level default.
            perm (int | None): Numeric OS permissions mode applied to the
                database directory and files.  ``None`` defaults to
                ``self.Perm``, which is more restrictive than the base class
                default in order to protect secret material.
            reopen (bool): When ``True`` the database environment is opened
                immediately inside ``__init__``.  Defaults to ``False``.
            **kwa: Additional keyword arguments forwarded to
                :class:`LMDBer.__init__` (e.g. ``name``, ``temp``).
        """
        if perm is None:
            perm = self.Perm  # defaults to restricted permissions for non temp

        super(Keeper, self).__init__(headDirPath=headDirPath, perm=perm,
                                     reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """Open or re-open the LMDB environment and all named sub-databases.

        Called by :meth:`__init__` when ``reopen=True`` and may be called
        again later to reattach after a close.  Creates each named
        sub-database the first time it is opened.  Sub-database names end
        with ``'.'`` to avoid namespace collisions with Base64 identifier
        prefixes.

        Args:
            **kwa: Keyword arguments forwarded to :meth:`LMDBer.reopen`.

        Returns:
            bool: ``True`` if the environment is open after this call,
            ``False`` otherwise (mirrors :attr:`LMDBer.opened`).
        """
        opened = super(Keeper, self).reopen(**kwa)

        # Create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.

        self.gbls = Suber(db=self, subkey='gbls.')
        self.pris = CryptSignerSuber(db=self, subkey='pris.')
        self.prxs = CesrSuber(db=self,
                                     subkey='prxs.',
                                     klas=Cipher)
        self.nxts = CesrSuber(db=self,
                                     subkey='nxts.',
                                     klas=Cipher)
        self.smids = CatCesrIoSetSuber(db=self,
                                              subkey='smids.',
                                              klas=(Prefixer, Number))
        self.rmids = CatCesrIoSetSuber(db=self,
                                              subkey='rmids.',
                                              klas=(Prefixer, Number))
        self.pres = CesrSuber(db=self,
                                     subkey='pres.',
                                     klas=Prefixer)
        self.prms = Komer(db=self,
                                 subkey='prms.',
                                 klas=PrePrm,)  # New Prefix Parameters
        self.sits = Komer(db=self,
                                 subkey='sits.',
                                 klas=PreSit,)  # Prefix Situation
        self.pubs = Komer(db=self,
                                 subkey='pubs.',
                                 klas=PubSet,)  # public key set at pre.ridx
        return self.opened


class KeeperDoer(doing.Doer):
    """Doer that manages the lifecycle of a :class:`Keeper` key-store database.

    Opens the :class:`Keeper` database on enter (if not already open) and
    closes it on exit, clearing the environment when the keeper was opened in
    temporary mode.

    Attributes:
        keeper (Keeper): The managed key-store database instance.

    Inherited Attributes:
        done (bool): Completion state. ``True`` means the doer finished
            normally; ``False`` means it is still running, was closed, or was
            aborted.

        tyme (float): Relative cycle time supplied by the injected
            :class:`Tymist`.

        tymth (callable): Closure that returns the associated
            :class:`Tymist`'s ``.tyme`` when called.

        tock (float): Desired seconds between recur calls. ``0`` means run
            as soon as possible.
    """

    def __init__(self, keeper, **kwa):
        """Initialize the KeeperDoer.

        Args:
            keeper (Keeper): The :class:`Keeper` instance whose lifecycle
                this doer manages.
            **kwa: Additional keyword arguments forwarded to
                :class:`doing.Doer.__init__`.
        """
        super(KeeperDoer, self).__init__(**kwa)
        self.keeper = keeper


    def enter(self, *, temp=None):
        """Open the keeper database if it is not already open.

        Called automatically when the doer enters its execution context.

        Args:
            temp (bool | None): Unused; present for interface compatibility.
        """
        if not self.keeper.opened:
            self.keeper.reopen()  # reopen(temp=temp)


    def exit(self):
        """Close the keeper database, clearing it if it was opened in temp mode.

        Called automatically when the doer exits its execution context,
        whether normally or due to an exception.
        """
        self.keeper.close(clear=self.keeper.temp)


class Creator:
    """Base class for key-pair creators.

    Defines the interface shared by all key-pair creation strategies.
    Subclasses override :meth:`create` to implement a specific algorithm
    (random re-keying, salt-path derivation, etc.).
    """

    def __init__(self, **kwa):
        """Initialize the Creator.

        Args:
            **kwa: Accepted for subclass compatibility; not used by the base
                class.
        """

    def create(self, **kwa):
        """Create and return key-pair signers.

        Args:
            **kwa: Algorithm-specific parameters defined by subclasses.

        Returns:
            list: Empty list in the base class; subclasses return a list of
            :class:`Signer` instances.
        """
        return []

    @property
    def salt(self):
        """str: The qb64 salt used by this creator, or empty string if none."""
        return ''

    @property
    def stem(self):
        """str: The path stem used by this creator, or empty string if none."""
        return ''

    @property
    def tier(self):
        """str: The security tier used by this creator, or empty string if none."""
        return ''


class RandyCreator(Creator):
    """Key-pair creator that generates a fresh random seed for every key pair.

    Each call to :meth:`create` independently randomizes the seed for each
    requested key pair, so key pairs produced by successive calls share no
    derivation relationship.
    """

    def __init__(self, **kwa):
        """Initialize the RandyCreator.

        Args:
            **kwa: Forwarded to :class:`Creator.__init__`.
        """
        super(RandyCreator, self).__init__(**kwa)

    def create(self, codes=None, count=1, code=MtrDex.Ed25519_Seed,
               transferable=True, **kwa):
        """Create and return a list of randomly keyed :class:`Signer` instances.

        When ``codes`` is not provided, ``count`` signers are created, each
        using ``code`` as their derivation code.

        Args:
            codes (list[str] | None): Derivation codes, one per key pair.
                When provided, its length determines the number of signers
                created and ``count`` / ``code`` are ignored.
            count (int): Number of key pairs to create when ``codes`` is not
                provided. Defaults to ``1``.
            code (str): Derivation code applied to all ``count`` key pairs
                when ``codes`` is not provided. Defaults to
                ``MtrDex.Ed25519_Seed``.
            transferable (bool): When ``True`` the signer uses a transferable
                derivation code; otherwise a non-transferable code is used.
                Defaults to ``True``.
            **kwa: Accepted for interface compatibility; not used.

        Returns:
            list[Signer]: One :class:`Signer` per requested key pair.
        """
        signers = []
        if not codes:  # if not codes make list len count of same code
            codes = [code for i in range(count)]

        for code in codes:
            signers.append(Signer(code=code, transferable=transferable))
        return signers


class SaltyCreator(Creator):
    """Key-pair creator that derives private keys from a salt using path stretching.

    Combines a root salt with a structured path string (built from the prefix
    index, rotation index, and key index) to deterministically derive each
    private key via the :class:`Salter` stretching algorithm.  The same salt
    and parameters always reproduce the same key pairs, enabling recovery.

    Attributes:
        salter (Salter): The :class:`Salter` instance that owns the root salt
            and performs the key-stretching derivation.
    """

    def __init__(self, salt=None, stem=None, tier=None, **kwa):
        """Initialize the SaltyCreator.

        Args:
            salt (str | None): Fully qualified qb64 root salt.  ``None``
                causes :class:`Salter` to generate a fresh random salt.
            stem (str | None): Unique path stem prepended to the per-key
                path when deriving private keys.  ``None`` or empty string
                causes the creator to use the hex-encoded ``pidx`` as the
                stem instead.
            tier (str | None): Security tier controlling the hashing work
                factor used during key stretching.  ``None`` defers to the
                :class:`Salter` default.
            **kwa: Forwarded to :class:`Creator.__init__`.
        """
        super(SaltyCreator, self).__init__(**kwa)
        self.salter = Salter(qb64=salt, tier=tier)
        self._stem = stem if stem is not None else ''

    @property
    def salt(self):
        """str: Fully qualified qb64 root salt owned by this creator."""
        return self.salter.qb64

    @property
    def stem(self):
        """str: The path stem component used during key derivation."""
        return self._stem

    @property
    def tier(self):
        """str: The security tier of the underlying :class:`Salter`."""
        return self.salter.tier

    def create(self, codes=None, count=1, code=MtrDex.Ed25519_Seed,
               pidx=0, ridx=0, kidx=0, transferable=True, temp=False, **kwa):
        """Create and return a list of deterministically derived :class:`Signer` instances.

        Constructs a unique derivation path for each key by concatenating the
        stem (or hex-encoded ``pidx`` when stem is empty), the hex rotation
        index ``ridx``, and the hex key index ``kidx + i``.  Each path is
        passed to :meth:`Salter.signer` to stretch the salt into a private
        key.

        Args:
            codes (list[str] | None): Derivation codes, one per key pair.
                When provided, its length determines the number of signers
                and ``count`` / ``code`` are ignored.
            count (int): Number of key pairs to create when ``codes`` is not
                provided. Defaults to ``1``.
            code (str): Derivation code applied to all ``count`` key pairs
                when ``codes`` is not provided. Defaults to
                ``MtrDex.Ed25519_Seed``.
            pidx (int): Prefix index identifying the key-pair sequence. Used
                as the stem when :attr:`stem` is empty. Defaults to ``0``.
            ridx (int): Rotation index of the establishment event for which
                these keys are created. Incorporated into the derivation
                path. Defaults to ``0``.
            kidx (int): Key index of the first key in the requested set
                within the overall key sequence. Defaults to ``0``.
            transferable (bool): When ``True`` the signer uses a transferable
                derivation code. Defaults to ``True``.
            temp (bool): When ``True`` bypasses the time-based work factor
                applied by the security tier, for use in tests.
                Defaults to ``False``.
            **kwa: Accepted for interface compatibility; not used.

        Returns:
            list[Signer]: One :class:`Signer` per requested key pair, in
            ascending key-index order.
        """
        signers = []
        if not codes:  # if not codes make list len count of same code
            codes = [code for i in range(count)]

        stem = self.stem if self.stem else "{:x}".format(pidx)  # if not stem use pidx
        for i, code in enumerate(codes):
            path = "{}{:x}{:x}".format(stem, ridx, kidx + i)
            signers.append(self.salter.signer(path=path,
                                              code=code,
                                              transferable=transferable,
                                              tier=self.tier,
                                              temp=temp))
        return signers


class Creatory:
    """Factory that constructs the appropriate :class:`Creator` subclass for a given algorithm.

    Example:
    
        .. code-block:: python

            creator = Creatory(algo=Algos.salty).make(salt='...')
    """

    def __init__(self, algo=Algos.salty):
        """Initialize the Creatory factory.

        Args:
            algo (str): Key-creation algorithm code.  Supported values are
                ``Algos.randy`` and ``Algos.salty``.

        Raises:
            ValueError: If ``algo`` is not a supported algorithm code.
        """
        if algo == Algos.randy:
            self._make = self._makeRandy
        elif algo == Algos.salty:
            self._make = self._makeSalty
        else:
            raise ValueError("Unsupported creation algorithm ={}.".format(algo))

    def make(self, **kwa):
        """Construct and return a :class:`Creator` subclass for the configured algorithm.

        Args:
            **kwa: Keyword arguments forwarded to the selected creator
                constructor (e.g. ``salt``, ``stem``, ``tier`` for
                :class:`SaltyCreator`).

        Returns:
            Creator: An instance of the creator subclass appropriate for the
            algorithm passed to :meth:`__init__`.
        """
        return (self._make(**kwa))


    def _makeRandy(self, **kwa):
        """Construct and return a :class:`RandyCreator`.

        Args:
            **kwa: Forwarded to :class:`RandyCreator.__init__`.

        Returns:
            RandyCreator: A new random-seed key-pair creator.
        """
        return RandyCreator(**kwa)


    def _makeSalty(self, **kwa):
        """Construct and return a :class:`SaltyCreator`.

        Args:
            **kwa: Forwarded to :class:`SaltyCreator.__init__`.

        Returns:
            SaltyCreator: A new salt-derived key-pair creator.
        """
        return SaltyCreator(**kwa)


# default values to init manager's globals database
Initage = namedtuple("Initage", 'aeid pidx salt tier')


class Manager:
    """Manages key pair creation, storage, retrieval, and message signing.

    Wraps a :class:`Keeper` key store and provides high-level operations—
    inception, rotation, signing, decryption, and replay—for one or more
    identifier prefixes.  All private key material and salts stored in the
    database may be encrypted at rest using an asymmetric key pair derived
    from an authentication and encryption identifier (``aeid``).

    The ``aeid`` public key is used to encrypt secrets; the corresponding
    private key (the ``seed``) is held only in memory and must never be
    written to the database.  Its presence authenticates the caller and
    enables decryption of stored secrets.

    Attributes:
        ks (Keeper): The key-store LMDB database used for persistence.
        encrypter (Encrypter | None): Encrypter derived from ``aeid``.
            ``None`` when no ``aeid`` is configured (i.e., no encryption at
            rest).
        decrypter (Decrypter | None): Decrypter derived from ``seed``.
            ``None`` when no ``aeid`` / ``seed`` is configured.
        inited (bool): ``True`` once :meth:`setup` has completed
            successfully.
    """

    def __init__(self, *, ks=None, seed=None, **kwa):
        """Initialize the Manager.

        When the :class:`Keeper` database is already open at construction
        time, :meth:`setup` is called immediately.  Otherwise,
        initialization is deferred until :meth:`setup` is called explicitly
        (or via :class:`ManagerDoer`).

        Args:
            ks (Keeper | None): Key store instance. A new default
                :class:`Keeper` opened with ``reopen=True`` is created when
                ``None``.
            seed (str | None): Fully qualified qb64 private signing key seed
                for ``aeid``. Held in memory only—never written to the
                database.  Required whenever an ``aeid`` is stored in the
                database in order to decrypt secrets and authenticate
                operations.  Only ``MtrDex.Ed25519_Seed`` is currently
                supported.
            **kwa: Keyword arguments forwarded to :meth:`setup` (``aeid``,
                ``pidx``, ``algo``, ``salt``, ``tier``). Captured in
                ``_inits`` for deferred initialization when the database is
                not yet open.
        """
        self.ks = ks if ks is not None else Keeper(reopen=True)
        self.encrypter = None
        self.decrypter = None
        self._seed = seed if seed is not None else ""
        self.inited = False

        # save keyword arg parameters to init later if db not opened yet
        self._inits = kwa

        if self.ks.opened:  # allows keeper db to opened asynchronously
            self.setup(**self._inits)  # first call to .setup with initialize database


    def setup(self, aeid=None, pidx=None, algo=None, salt=None, tier=None):
        """Initialize or validate the manager's root attributes in the database.

        Must be called with the keeper database open.  On the first ever
        call (vacuous initialization), missing global parameters are written
        to the database from the supplied arguments or their defaults.  On
        subsequent calls, the existing database values are used and the
        provided ``aeid`` and ``seed`` are verified for consistency.

        Supports deferred initialization: if the keeper database was not
        open when :meth:`__init__` was called, this method can be invoked
        later once the database becomes available (e.g., via
        :class:`ManagerDoer`).

        Args:
            aeid (str | None): Fully qualified qb64 non-transferable
                identifier prefix for authentication and encryption.
                Behavior depends on the relationship to the value already
                stored:

                * Same as stored value — no-op.
                * Different non-empty value — re-encrypts all secrets and
                  updates the stored aeid.  Requires ``seed`` to match the
                  new ``aeid``.
                * Empty string or ``None`` — treated as empty string;
                  decrypts all secrets and removes the aeid, disabling
                  encryption at rest.

            pidx (int | None): Initial value for the prefix index.  Only
                used during vacuous initialization; ignored if already set.
                Defaults to ``0``.
            algo (str | None): Default root algorithm code.  Only used
                during vacuous initialization. Defaults to ``Algos.salty``.
            salt (str | None): Fully qualified qb64 root salt.  Only used
                during vacuous initialization; a fresh random salt is
                generated when ``None``.  Must be valid qb64 if provided.
            tier (str | None): Default security tier.  Only used during
                vacuous initialization. Defaults to ``Tiers.low``.

        Raises:
            ClosedError: If the keeper database is not open.
            ValueError: If ``salt`` is provided but is not valid qb64.
            AuthError: If an ``aeid`` is already stored and the in-memory
                ``seed`` is missing or does not correspond to that ``aeid``.
        """
        if not self.ks.opened:
            raise ClosedError("Attempt to setup Manager closed keystore"
                                     " database .ks.")

        if aeid is None:
            aeid = ''
        if pidx is None:
            pidx = 0
        if algo is None:
            algo = Algos.salty
        if salt is None:
            salt = Salter().qb64
        else:
            if Salter(qb64=salt).qb64 != salt:
                raise ValueError(f"Invalid qb64 for salt={salt}.")

        if tier is None:
            tier = Tiers.low

        # update  database if never before initialized
        if self.pidx is None:  # never before initialized
            self.pidx = pidx  # init to default

        if self.algo is None:  # never before initialized
            self.algo = algo

        if self.salt is None:  # never before initialized
            self.salt = salt

        if self.tier is None:  # never before initialized
            self.tier = tier  # init to default

        # must do this after salt is initialized so gets re-encrypted correctly
        if not self.aeid:  # never before initialized
            self.updateAeid(aeid, self.seed)
        else:
            self.encrypter = Encrypter(verkey=self.aeid)  # derive encrypter from aeid
            if not self.seed or not self.encrypter.verifySeed(self.seed):
                raise AuthError("Last seed missing or provided last seed "
                                       "not associated with last aeid={}."
                                       "".format(self.aeid))

            self.decrypter = Decrypter(seed=self.seed)

        self.inited = True

    def updateAeid(self, aeid, seed):
        """Update the authentication/encryption identifier and re-encrypt all stored secrets.

        Verifies that ``seed`` corresponds to the current ``aeid`` (when one
        is stored), verifies that ``seed`` corresponds to the new ``aeid``
        (when one is provided), re-encrypts all secrets (root salt, prefix
        salts, private signing keys) with the new encrypter, and persists
        the updated ``aeid`` to the database.

        Providing an empty ``aeid`` removes encryption at rest: all secrets
        are stored as plain text and no ``aeid`` is persisted.

        Args:
            aeid (str): Fully qualified qb64 of the new authentication and
                encryption identifier (public signing key), or empty string
                to disable encryption at rest.
            seed (str): Fully qualified qb64 private signing key seed
                corresponding to ``aeid``.  Required when ``aeid`` is
                non-empty.

        Raises:
            AuthError: If a current ``aeid`` is stored and the current
                in-memory ``seed`` does not verify against it, or if the
                provided ``seed`` does not verify against the new ``aeid``.
        """
        if self.aeid:  # check that last current seed matches last current .aeid
            # verifies seed belongs to aeid
            if not self.seed or not self.encrypter.verifySeed(self.seed):
                raise AuthError("Last seed missing or provided last seed "
                                       "not associated with last aeid={}."
                                       "".format(self.aeid))

        if aeid:  # aeid provided
            if aeid != self.aeid:  # changing to a new aeid so update .encrypter
                self.encrypter = Encrypter(verkey=aeid)  # derive encrypter from aeid
                # verifies new seed belongs to new aeid
                if not seed or not self.encrypter.verifySeed(seed):
                    raise AuthError("Seed missing or provided seed not associated"
                                           "  with provided aeid={}.".format(aeid))
        else:  # changing to empty aeid so new encrypter is None
            self.encrypter = None

        # fetch all secrets from db, decrypt all secrets with self.decrypter
        # unless they decrypt automatically on fetch and then re-encrypt with
        # encrypter  update db with re-encrypted values

        # re-encypt root salt secret, .salt property is automatically decrypted on fetch
        if (salt := self.salt) is not None:  # decrypted salt
            self.salt = salt
            # self.salt = self.encrypter.encrypt(ser=salt).qb64 if self.encrypter else salt

        # other secrets
        if self.decrypter:
            # re-encrypt root salt secrets by prefix parameters .prms
            for keys, data in self.ks.prms.getTopItemIter():  # keys is tuple of pre qb64
                if data.salt:
                    salter = self.decrypter.decrypt(qb64=data.salt)
                    data.salt = (self.encrypter.encrypt(prim=salter).qb64
                                 if self.encrypter else salter.qb64)
                    self.ks.prms.pin(keys, val=data)

            # private signing key seeds
            # keys is tuple == (verkey.qb64,) .pris database auto decrypts
            for keys, signer in self.ks.pris.getTopItemIter(decrypter=self.decrypter):
                self.ks.pris.pin(keys, signer, encrypter=self.encrypter)

        self.ks.gbls.pin("aeid", aeid)  # set aeid in db
        self._seed = seed  # set .seed in memory

        # update .decrypter
        self.decrypter = Decrypter(seed=seed) if seed else None


    @property
    def seed(self):
        """str: In-memory qb64 private signing key seed associated with ``aeid``.

        Never persisted to the database.
        """
        return self._seed


    @property
    def aeid(self):
        """str: Fully qualified qb64 non-transferable identifier prefix for authentication and encryption.

        Read from the keeper database.  Empty string means no ``aeid`` is
        configured and encryption at rest is disabled.
        """
        return self.ks.gbls.get('aeid')


    @property
    def pidx(self):
        """int | None: Index of the next prefix key-pair sequence to be incepted.

        Read from the keeper database (stored as a hex string).  ``None``
        when the database has not yet been initialized.
        """
        if (pidx := self.ks.gbls.get("pidx")) is not None:
            return int(pidx, 16)
        return pidx  # None


    @pidx.setter
    def pidx(self, pidx):
        """Set the prefix index in the keeper database.

        Args:
            pidx (int): New prefix index value.  Stored as a hex string.
        """
        self.ks.gbls.pin("pidx", "%x" % pidx)


    @property
    def algo(self):
        """str | None: Default root algorithm code for creating key pairs.

        Read from the keeper database.  ``None`` when the database has not
        yet been initialized.
        """
        return self.ks.gbls.get('algo')


    @algo.setter
    def algo(self, algo):
        """Set the default root algorithm code in the keeper database.

        Args:
            algo (str): Algorithm code to store (e.g. ``Algos.salty``).
        """
        self.ks.gbls.pin('algo', algo)


    @property
    def salt(self):
        """str | None: Fully qualified qb64 root salt for new key sequence creation.

        Read from the keeper database.  When :attr:`decrypter` is set the
        value is automatically decrypted before being returned, so callers
        always receive plaintext qb64.  ``None`` when the database has not
        yet been initialized.
        """
        salt = self.ks.gbls.get('salt')
        if self.decrypter:  # given .decrypt secret salt must be encrypted in db
            return self.decrypter.decrypt(qb64=salt).qb64
        return salt


    @salt.setter
    def salt(self, salt):
        """Store the root salt in the keeper database, encrypting it when configured.

        Args:
            salt (str): Fully qualified qb64 root salt.  Encrypted with the
                current :attr:`encrypter` before storage when one is
                configured; stored as plain qb64 otherwise.
        """
        if self.encrypter:
            salt = self.encrypter.encrypt(ser=salt, code=MtrDex.X25519_Cipher_Salt).qb64
        self.ks.gbls.pin('salt', salt)


    @property
    def tier(self):
        """str | None: Default security tier for the root salt.

        Read from the keeper database.  ``None`` when the database has not
        yet been initialized.
        """
        return self.ks.gbls.get('tier')


    @tier.setter
    def tier(self, tier):
        """Set the default security tier in the keeper database.

        Args:
            tier (str): Security tier value (e.g. a member of
                :class:`Tiers`).
        """
        self.ks.gbls.pin('tier', tier)


    def incept(self, icodes=None, icount=1, icode=MtrDex.Ed25519_Seed,
                     ncodes=None, ncount=1, ncode=MtrDex.Ed25519_Seed,
                     dcode=MtrDex.Blake3_256,
                     algo=None, salt=None, stem=None, tier=None, rooted=True,
                     transferable=True, temp=False):
        """Create and store key pairs for a new identifier prefix inception event.

        Generates the current signing key set (``isigners``) and the
        pre-committed next key set (``nsigners``), stores all private keys
        and public key sets in the database, initializes :class:`PrePrm` and
        :class:`PreSit` records, and increments :attr:`pidx`.

        Because the permanent identifier prefix is typically only known after
        the inception event is constructed (e.g. self-addressing identifiers
        require the event body to derive the prefix), the key material is
        initially indexed under the first public key acting as a temporary
        prefix.  Call :meth:`move` afterwards to migrate the records to the
        permanent prefix.

        Args:
            icodes (list[str] | None): Derivation codes for each inception
                key pair.  When ``None``, ``icount`` key pairs are created
                using ``icode``.
            icount (int): Number of inception key pairs to create when
                ``icodes`` is ``None``.  Must be ``> 0``. Defaults to ``1``.
            icode (str): Derivation code for all inception key pairs when
                ``icodes`` is ``None``. Defaults to ``MtrDex.Ed25519_Seed``.
            ncodes (list[str] | None): Derivation codes for each next key
                pair.  When ``None``, ``ncount`` key pairs are created using
                ``ncode``.
            ncount (int): Number of next key pairs to create when ``ncodes``
                is ``None``.  ``0`` produces an empty next key set, making
                the prefix effectively non-transferable. Defaults to ``1``.
            ncode (str): Derivation code for all next key pairs when
                ``ncodes`` is ``None``. Defaults to ``MtrDex.Ed25519_Seed``.
            dcode (str): Derivation code for the digest of each next public
                key (used to build the pre-rotation commitment).
                Defaults to ``MtrDex.Blake3_256``.
            algo (str | None): Key-creation algorithm.  ``None`` inherits
                the root algorithm from the database when ``rooted=True``.
            salt (str | None): qb64 salt for the salty algorithm.  ``None``
                inherits the root salt from the database when ``rooted=True``.
            stem (str | None): Path stem for key derivation.  ``None`` causes
                the creator to use the hex-encoded ``pidx`` as the stem.
            tier (str | None): Security tier.  ``None`` inherits the root
                tier from the database when ``rooted=True``.
            rooted (bool): When ``True``, ``algo``, ``salt``, and ``tier``
                default to the root values stored in the database.
                Defaults to ``True``.
            transferable (bool): When ``True`` each key pair uses a
                transferable derivation code.  Set to ``False`` only for
                basic non-transferable identifier derivation.
                Defaults to ``True``.
            temp (bool): When ``True`` bypasses the time-based key-stretching
                work factor, for use in tests. Defaults to ``False``.

        Returns:
            tuple[list[Verfer], list[Diger]]: A two-element tuple:

            * **verfers** — one :class:`Verfer` per inception signing key;
              ``verfer.qb64`` is the public key.
            * **digers** — one :class:`Diger` per next public key;
              ``diger.raw`` is the pre-rotation digest used in the inception
              event's ``n`` field.

        Raises:
            ValueError: If ``icount <= 0``, ``ncount < 0``, or if key
                material for the derived prefix already exists in the
                database.
        """
        # get root defaults to initialize key sequence
        if rooted and algo is None:  # use root algo from db as default
            algo = self.algo

        if rooted and salt is None:  # use root salt from db instead of random salt
            salt = self.salt

        if rooted and tier is None:  # use root tier from db as default
            tier = self.tier

        pidx = self.pidx  # get next pidx
        ridx = 0  # rotation index
        kidx = 0  # key pair index

        creator = Creatory(algo=algo).make(salt=salt, stem=stem, tier=tier)

        if not icodes:  # all same code, make list of len icount of same code
            if icount <= 0:
                raise ValueError("Invalid icount={} must be > 0.".format(icount))
            icodes = [icode for i in range(icount)]

        isigners = creator.create(codes=icodes,
                                  pidx=pidx, ridx=ridx, kidx=kidx,
                                  transferable=transferable, temp=temp)
        verfers = [signer.verfer for signer in isigners]

        if not ncodes:  # all same code, make list of len ncount of same code
            if ncount < 0:  # next may be zero if non-trans
                raise ValueError("Invalid ncount={} must be >= 0.".format(ncount))
            ncodes = [ncode for i in range(ncount)]

        # count set to 0 to ensure does not create signers if ncodes is empty
        nsigners = creator.create(codes=ncodes, count=0,
                                  pidx=pidx, ridx=ridx+1, kidx=kidx+len(icodes),
                                  transferable=transferable, temp=temp)
        digers = [Diger(ser=signer.verfer.qb64b, code=dcode) for signer in nsigners]

        # Secret to encrypt here
        pp = PrePrm(pidx=pidx,
                    algo=algo,
                    stem=creator.stem,
                    tier=creator.tier)

        if creator.salt:
            pp.salt = (creator.salt if not self.encrypter
                       else self.encrypter.encrypt(ser=creator.salt,
                                    code=MtrDex.X25519_Cipher_Salt).qb64)

        dt = nowIso8601()
        ps = PreSit(
                    new=PubLot(pubs=[verfer.qb64 for verfer in verfers],
                                   ridx=ridx, kidx=kidx, dt=dt),
                    nxt=PubLot(pubs=[signer.verfer.qb64 for signer in nsigners],
                                   ridx=ridx+1, kidx=kidx+len(icodes), dt=dt))

        pre = verfers[0].qb64b
        if not self.ks.pres.put(pre, val=Prefixer(qb64=pre)):
            raise ValueError("Already incepted pre={}.".format(pre.decode("utf-8")))

        if not self.ks.prms.put(pre, val=pp):
            raise ValueError("Already incepted prm for pre={}.".format(pre.decode("utf-8")))

        self.pidx = pidx + 1  # increment for next inception

        if not self.ks.sits.put(pre, val=ps):
            raise ValueError("Already incepted sit for pre={}.".format(pre.decode("utf-8")))

        for signer in isigners:  # store secrets (private key val keyed by public key)
            self.ks.pris.put(keys=signer.verfer.qb64b, val=signer,
                             encrypter=self.encrypter)

        self.ks.pubs.put(riKey(pre, ri=ridx), val=PubSet(pubs=ps.new.pubs))

        for signer in nsigners:  # store secrets (private key val keyed by public key)
            self.ks.pris.put(keys=signer.verfer.qb64b, val=signer,
                             encrypter=self.encrypter)

        # store publics keys for lookup of private key for replay
        self.ks.pubs.put(riKey(pre, ri=ridx+1), val=PubSet(pubs=ps.nxt.pubs))

        return (verfers, digers)


    def move(self, old, new):
        """Reassign key-pair database records from a temporary prefix to the permanent prefix.

        After :meth:`incept`, records are stored under the first public key
        as a temporary prefix.  Once the permanent identifier prefix is
        known, this method copies the :class:`PrePrm`, :class:`PreSit`, and
        all :class:`PubSet` records from ``old`` to ``new``, then removes
        the ``prms`` and ``sits`` entries for ``old``.  Note that ``pubs``
        entries for ``old`` are copied but not deleted from the database.

        The ``pres`` entry for ``old`` is updated to point to ``new``, and a
        new ``pres`` entry for ``new`` is inserted so that future move
        attempts on ``new`` can be detected.

        If ``old == new``, this method returns immediately without any
        changes.

        Args:
            old (str): The old (temporary) identifier prefix under which
                records are currently stored.
            new (str): The new (permanent) identifier prefix to migrate
                records to.

        Raises:
            ValueError: If ``old`` does not exist in ``ks.pres``, ``new``
                already exists in ``ks.pres``, or if any database put/pin
                operation fails.
        """
        if old == new:
            return

        if self.ks.pres.get(old) is None:
            raise ValueError("Nonexistent old pre={}, nothing to assign.".format(old))

        if self.ks.pres.get(new) is not None:
            raise ValueError("Preexistent new pre={} may not clobber.".format(new))

        if (oldprm := self.ks.prms.get(old)) is None:
            raise ValueError("Nonexistent old prm for pre={}, nothing to move.".format(old))

        if self.ks.prms.get(new) is not None:
            raise ValueError("Preexistent new prm for pre={} may not clobber.".format(new))

        if (oldsit := self.ks.sits.get(old)) is None:
            raise ValueError("Nonexistent old sit for pre={}, nothing to move.".format(old))

        if self.ks.sits.get(new) is not None:
            raise ValueError("Preexistent new sit for pre={} may not clobber.".format(new))

        if not self.ks.prms.put(new, val=oldprm):
            raise ValueError("Failed moving prm from old pre={} to new pre={}.".format(old, new))
        else:
            self.ks.prms.rem(old)

        if not self.ks.sits.put(new, val=oldsit):
            raise ValueError("Failed moving sit from old pre={} to new pre={}.".format(old, new))
        else:
            self.ks.sits.rem(old)

        # move .pubs entries if any
        i = 0
        while (pl := self.ks.pubs.get(riKey(old, i))):
            if not self.ks.pubs.put(riKey(new, i), val=pl):
                raise ValueError("Failed moving pubs at pre={} ri={} to new"
                                 " pre={}".format(old, i, new))
            i += 1

        # assign old
        if not self.ks.pres.pin(old, val=Prefixer(qb64=new)):
            raise ValueError("Failed assiging new pre={} to old pre={}.".format(new, old))

        # make new so that if move again we reserve each one
        if not self.ks.pres.put(new, val=Prefixer(qb64=new)):
            raise ValueError("Failed assiging new pre={}.".format(new))


    def rotate(self, pre, ncodes=None, ncount=1,
                     ncode=MtrDex.Ed25519_Seed,
                     dcode=MtrDex.Blake3_256,
                     transferable=True, temp=False, erase=True):
        """Rotate the signing keys for an existing identifier prefix.

        Promotes the pre-committed next key set (``ps.nxt``) to become the
        new current signing key set (``ps.new``), generates a fresh next key
        set for the subsequent rotation, and persists all changes to the
        database.

        The three-slot :class:`PreSit` shifts by one on each call:

        * Pre-call ``ps.old`` (keys from two rotations ago) — erased from
          ``ks.pris`` when ``erase=True``.
        * Pre-call ``ps.new`` (the just-superseded signing set) — becomes
          the new ``ps.old``.
        * Pre-call ``ps.nxt`` (the pre-committed set) — becomes the new
          ``ps.new`` (active signers).
        * Newly generated signers — stored as the new ``ps.nxt``.

        Args:
            pre (str): Fully qualified qb64 identifier prefix to rotate.
            ncodes (list[str] | None): Derivation codes for each new next
                key pair.  When ``None``, ``ncount`` key pairs are created
                using ``ncode``.
            ncount (int): Number of next key pairs to create when ``ncodes``
                is ``None``.  ``0`` produces an empty next key set, making
                the prefix non-transferable after this rotation.
                Defaults to ``1``.
            ncode (str): Derivation code for all next key pairs when
                ``ncodes`` is ``None``. Defaults to ``MtrDex.Ed25519_Seed``.
            dcode (str): Derivation code for the digest of each next public
                key. Defaults to ``MtrDex.Blake3_256``.
            transferable (bool): When ``True`` each key pair uses a
                transferable derivation code. Defaults to ``True``.
            temp (bool): When ``True`` bypasses the time-based key-stretching
                work factor, for use in tests. Defaults to ``False``.
            erase (bool): When ``True`` the private keys of the pre-call
                ``ps.old`` set (keys from two rotations ago) are deleted
                from ``ks.pris``. Defaults to ``True``.

        Returns:
            tuple[list[Verfer], list[Diger]]: A two-element tuple:

            * **verfers** — one :class:`Verfer` per key in the newly active
              signing key set; ``verfer.qb64`` is the public key.
            * **digers** — one :class:`Diger` per key in the new next
              (pre-committed) key set; ``diger.raw`` is the pre-rotation
              digest.

        Raises:
            ValueError: If ``pre`` has no stored :class:`PrePrm` or
                :class:`PreSit`, if the prefix is already non-transferable
                (empty ``ps.nxt`` public keys), or if ``ncount < 0``.
            DecryptError: If an ``aeid`` is configured but no decrypter is
                available (i.e. ``seed`` was not provided).
        """
        # Secret to decrypt here
        if (pp := self.ks.prms.get(pre)) is None:
            raise ValueError("Attempt to rotate nonexistent pre={}.".format(pre))

        if (ps := self.ks.sits.get(pre)) is None:
            raise ValueError("Attempt to rotate nonexistent pre={}.".format(pre))

        if not ps.nxt.pubs:  # empty nxt public keys so non-transferable prefix
            raise ValueError("Attempt to rotate nontransferable pre={}.".format(pre))

        old = ps.old  # save prior old so can clean out if rotate successful
        ps.old = ps.new  # move prior new to old so save previous one step
        ps.new = ps.nxt  # move prior nxt to new which new is now current signer

        verfers = []  # assign verfers from current new was prior nxt
        for pub in ps.new.pubs:
            if self.aeid and not self.decrypter:  # maybe should rethink this
                raise DecryptError("Unauthorized decryption attempt. "
                                          "Aeid but no decrypter.")

            if ((signer := self.ks.pris.get(pub.encode("utf-8"),
                                           decrypter=self.decrypter)) is None):
                raise ValueError("Missing prikey in db for pubkey={}".format(pub))
            verfers.append(signer.verfer)

        salt = pp.salt
        if salt:
            if self.aeid:
                if not self.decrypter:
                    raise DecryptError("Unauthorized decryption. Aeid but no decrypter.")
                salt = self.decrypter.decrypt(qb64=salt).qb64
            else:
                salt = Salter(qb64=salt).qb64  # ensures salt was unencrypted

        creator = Creatory(algo=pp.algo).make(salt=salt, stem=pp.stem, tier=pp.tier)

        if not ncodes:  # all same code, make list of len count of same code
            if ncount < 0:  # next may be zero if non-trans
                raise ValueError("Invalid count={} must be >= 0.".format(ncount))
            ncodes = [ncode for i in range(ncount)]

        pidx = pp.pidx  # get pidx for this key sequence, may be used by salty creator
        ridx = ps.new.ridx + 1
        kidx = ps.nxt.kidx + len(ps.new.pubs)

        # count set to 0 to ensure does not create signers if codes is empty
        signers = creator.create(codes=ncodes, count=0,
                                 pidx=pidx, ridx=ridx, kidx=kidx,
                                 transferable=transferable, temp=temp)
        digers = [Diger(ser=signer.verfer.qb64b, code=dcode) for signer in signers]

        dt = nowIso8601()
        ps.nxt = PubLot(pubs=[signer.verfer.qb64 for signer in signers],
                              ridx=ridx, kidx=kidx, dt=dt)

        if not self.ks.sits.pin(pre, val=ps):
            raise ValueError("Problem updating pubsit db for pre={}.".format(pre))

        for signer in signers:  # store secrets (private key val keyed by public key)
            self.ks.pris.put(keys=signer.verfer.qb64b, val=signer,
                             encrypter=self.encrypter)

        # store public keys for lookup of private keys by public key for replay
        self.ks.pubs.put(riKey(pre, ri=ps.nxt.ridx), val=PubSet(pubs=ps.nxt.pubs))

        if erase:
            for pub in old.pubs:  # remove prior old prikeys not current old
                self.ks.pris.rem(pub)

        return (verfers, digers)


    def sign(self, ser, pubs=None, verfers=None, indexed=True,
             indices=None, ondices=None, pre=None, path=None):
        """Sign a serialization with one or more stored private keys.

        Looks up the private key for each requested public key in the keeper
        database and returns a list of signatures.  When ``indexed=True``
        each signature is an indexed :class:`Siger`; when ``indexed=False``
        each is a :class:`Cigar` with ``.verfer`` assigned.

        Exactly one of ``pubs``, ``verfers``, or ``pre`` must be provided.
        When both ``pubs`` and ``verfers`` are given, ``verfers`` is ignored.

        The ``indices`` parameter allows the caller to specify the index
        value embedded in each :class:`Siger`, decoupling it from the
        position of the signer in ``pubs`` / ``verfers``.  This is necessary
        for witness or multi-sig scenarios where different parties maintain
        independent key stores with different key orderings.

        The ``ondices`` parameter allows the caller to embed a second index
        into each :class:`Siger`, used in partial-rotation or custodial key
        management to indicate a key's position in the prior next list when
        it differs from its position in the current signing list.  A ``None``
        entry in ``ondices`` means no ondex for that signer.

        Note:
            The ``pre`` / ``path`` code path is currently unimplemented.
            Providing ``pre`` without ``pubs`` or ``verfers`` will result in
            a ``TypeError`` when the subsequent iteration over ``verfers``
            (which is ``None``) is attempted.

        Args:
            ser (bytes): The serialized data to sign.
            pubs (list[str] | None): Fully qualified qb64 public keys whose
                private keys are looked up in the database.  Takes precedence
                over ``verfers`` when both are provided.
            verfers (list[Verfer] | None): :class:`Verfer` instances whose
                ``.qb64`` public keys are used for lookup.  Ignored when
                ``pubs`` is provided.
            indexed (bool): When ``True`` return indexed :class:`Siger`
                instances; when ``False`` return :class:`Cigar` instances.
                Defaults to ``True``.
            indices (list[int] | None): Explicit index values for each
                returned :class:`Siger`, overriding the default positional
                index.  Length must match the number of signers when
                provided.
            ondices (list[int | None] | None): Explicit other-index (ondex)
                values for each returned :class:`Siger`.  A ``None`` entry
                marks a signature as having no ondex (current-key-only).
                Length must match the number of signers when provided.
            pre (str | None): Reserved for future HDK salty-algorithm key
                lookup.  Currently unimplemented; see Note above.
            path (tuple | None): Reserved for future HDK path derivation
                as ``(ridx, kidx)``.  Currently unimplemented.

        Returns:
            list[Siger] | list[Cigar]: When ``indexed=True``, a list of
            :class:`Siger` instances, one per signer.  When
            ``indexed=False``, a list of :class:`Cigar` instances with
            ``.verfer`` assigned.

        Raises:
            ValueError: If none of ``pubs`` or ``verfers`` is provided and
                ``pre`` is also ``None``; if a public key has no
                corresponding private key in the database; or if the length
                of ``indices`` or ``ondices`` does not match the number of
                signers.
            DecryptError: If an ``aeid`` is configured but no decrypter is
                available.
        """
        signers = []

        if pubs is None and verfers is None:
            if pre is None:
                raise ValueError("pubs or verfers or pre required")

            # logic here to generate paths
            # use pre to read .ks.prms and .ks.sits to get algo stem and pidx and
            # sits .old an .new for pre
            if path is None:  # use provided path tuple for .new or .nxt
                pass
                # defualt path is .new.ridx and .new.kidx

            # compute paths
            # if indices provided use indices to compute kidxes
            # otherwise default is all the keys from the .new key list so use
            # .nxt to comput number of keys to generate kidxes for paths
            paths = []
            # use paths to generate signers

        if pubs:
            for pub in pubs:
                if self.aeid and not self.decrypter:
                    raise DecryptError("Unauthorized decryption attempt. "
                                              "Aeid but no decrypter.")
                if ((signer := self.ks.pris.get(pub, decrypter=self.decrypter))
                        is None):
                    raise ValueError("Missing prikey in db for pubkey={}".format(pub))
                signers.append(signer)

        else:
            for verfer in verfers:
                if self.aeid and not self.decrypter:
                    raise DecryptError("Unauthorized decryption attempt. "
                                              "Aeid but no decrypter.")
                if ((signer := self.ks.pris.get(verfer.qb64,
                                                decrypter=self.decrypter))
                        is None):
                    raise ValueError("Missing prikey in db for pubkey={}".format(verfer.qb64))
                signers.append(signer)

        if indices and len(indices) != len(signers):
            raise ValueError(f"Mismatch indices length={len(indices)} and resultant"
                             f" signers length={len(signers)}")

        if ondices and len(ondices) != len(signers):
            raise ValueError(f"Mismatch ondices length={len(ondices)} and resultant"
                             f" signers length={len(signers)}")

        if indexed:
            sigers = []
            for j, signer in enumerate(signers):
                if indices:  # not the default get index from indices
                    i = indices[j]  # must be whole number
                    if not isinstance(i, int) or i < 0:
                        raise ValueError(f"Invalid signing index = {i}, not "
                                         f"whole number.")
                else:  # the default
                    i = j  # same index as database

                if ondices:  # not the default get ondex from ondices
                    o = ondices[j]  # int means both, None means current only
                    if not (o is None or
                            isinstance(o, int) and not isinstance(o, bool) and o >= 0):
                        raise ValueError(f"Invalid other signing index = {o}, not "
                                         f"None or not whole number.")
                else:  # default
                    o = i  # must both be same value int
                # .sign assigns .verfer of siger and sets code of siger
                # appropriately for single or dual indexed signatures
                sigers.append(signer.sign(ser,
                                          index=i,
                                          only=True if o is None else False,
                                          ondex=o))
            return sigers

        else:
            cigars = []
            for signer in signers:
                cigars.append(signer.sign(ser))  # assigns .verfer to cigar
            return cigars


    def decrypt(self, qb64, pubs=None, verfers=None):
        """Decrypt a sealed ciphertext using a stored private key.

        Looks up the private signing key for each provided public key,
        converts it to a Curve25519 private decryption key via
        :func:`pysodium.crypto_sign_sk_to_box_sk`, and attempts to open the
        sealed box ciphertext ``qb64`` with each key pair in turn.  Only the
        result of the final successful decryption is returned; provide a
        single public key in the normal case.

        Args:
            qb64 (str | bytes | bytearray | memoryview): Fully qualified
                Base64 sealed-box ciphertext to decrypt.
            pubs (list[str] | None): Fully qualified qb64 public keys whose
                corresponding private keys are used for decryption.  Takes
                precedence over ``verfers`` when both are provided.
            verfers (list[Verfer] | None): :class:`Verfer` instances whose
                ``.qb64`` public keys are used for lookup.  Ignored when
                ``pubs`` is provided.

        Returns:
            bytes: The decrypted plaintext bytes from the last signer
            attempted.

        Raises:
            ValueError: If a public key has no corresponding private key in
                the database, or if the plaintext equals the ciphertext after
                all decryption attempts (indicating failure).
            DecryptError: If an ``aeid`` is configured but no decrypter is
                available.
        """
        signers = []
        if pubs:
            for pub in pubs:
                if self.aeid and not self.decrypter:
                    raise DecryptError("Unauthorized decryption attempt. "
                                              "Aeid but no decrypter.")
                if ((signer := self.ks.pris.get(pub, decrypter=self.decrypter))
                        is None):
                    raise ValueError("Missing prikey in db for pubkey={}".format(pub))
                signers.append(signer)

        else:
            for verfer in verfers:
                if self.aeid and not self.decrypter:
                    raise DecryptError("Unauthorized decryption attempt. "
                                              "Aeid but no decrypter.")
                if ((signer := self.ks.pris.get(verfer.qb64,
                                                decrypter=self.decrypter))
                        is None):
                    raise ValueError("Missing prikey in db for pubkey={}".format(verfer.qb64))
                signers.append(signer)

        if hasattr(qb64, "encode"):
            qb64 = qb64.encode()  # convert str to bytes
        qb64 = bytes(qb64)  # convert bytearray or memoryview to bytes

        for signer in signers:
            sigkey = signer.raw + signer.verfer.raw  # sigkey is raw seed + raw verkey
            prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)  # raw private encrypt key
            pubkey = pysodium.crypto_scalarmult_curve25519_base(prikey)
            plain = pysodium.crypto_box_seal_open(qb64, pubkey, prikey)  # qb64b

        if plain == qb64:
            raise ValueError(f"Unable to decrypt.")

        return plain


    def ingest(self, secrecies, iridx=0, ncount=1, ncode=MtrDex.Ed25519_Seed,
                     dcode=MtrDex.Blake3_256,
                     algo=Algos.salty, salt=None, stem=None, tier=None,
                     rooted=True, transferable=True, temp=False):
        """Import an externally generated key sequence and register it in the database.

        Ingests a list of lists of private key secrets (``secrecies``),
        where each inner list corresponds to the signing key set for one
        establishment event in order (inception first, then successive
        rotations).  All ingested private keys are stored in the database
        with encryption applied when configured.  After the last ingested
        set, a new next key set is generated using the specified algorithm
        and parameters, exactly as if a rotation had been performed.

        Unlike :meth:`rotate`, ingest does not delete any of the ingested
        private keys.  The caller is responsible for erasing stale keys if
        desired.

        Note:
            The newly generated ``nsigners`` (keys after the ingested
            sequence) are stored in ``ks.pris`` without applying the
            :attr:`encrypter`, even when one is configured.  This is
            inconsistent with the treatment of ingested keys and may be
            addressed in a future revision.

        The ``iridx`` parameter controls which ingested key set is treated
        as the current active set (``ps.new``):

        * The set at ``iridx - 1`` (or a default empty lot when
          ``iridx == 0``) becomes ``ps.old``.
        * The set at ``iridx`` becomes ``ps.new``.
        * The set at ``iridx + 1`` (or the newly generated set when
          ``len(secrecies) == iridx + 1``) becomes ``ps.nxt``.

        Typical use cases are import from an external key store and recovery
        from backup.

        Args:
            secrecies (list[list[str]]): Ordered list of lists of fully
                qualified qb64 private key secrets.  The outer list is in
                establishment event order; each inner list contains the
                secrets for one establishment event's signing key set.
            iridx (int): Rotation index into ``secrecies`` that marks the
                currently active key set.  Must satisfy
                ``0 <= iridx <= len(secrecies)``. Defaults to ``0``.
            ncount (int): Number of next key pairs to generate after the
                last ingested set. Defaults to ``1``.
            ncode (str): Derivation code for each generated next key pair.
                Defaults to ``MtrDex.Ed25519_Seed``.
            dcode (str): Derivation code for next key digests.
                Defaults to ``MtrDex.Blake3_256``.
            algo (str): Key-creation algorithm for generating the new next
                keys after the end of ``secrecies``.
                Defaults to ``Algos.salty``.
            salt (str | None): qb64 salt for key derivation.  ``None``
                inherits the root salt when ``rooted=True``.
            stem (str | None): Path stem for key derivation.  ``None``
                causes the creator to use the hex-encoded ``pidx`` as the
                stem.
            tier (str | None): Security tier.  ``None`` inherits the root
                tier when ``rooted=True``.
            rooted (bool): When ``True`` ``salt`` and ``tier`` default to
                the root values stored in the database.
                Defaults to ``True``.
            transferable (bool): When ``True`` each key pair uses a
                transferable derivation code. Defaults to ``True``.
            temp (bool): When ``True`` bypasses the time-based
                key-stretching work factor, for use in tests.
                Defaults to ``False``.

        Returns:
            tuple[str, list[list[Verfer]]]: A two-element tuple:

            * **ipre** — the qb64 first public key of the ingested sequence,
              used as the initial (temporary) prefix for subsequent
              :meth:`move` calls.
            * **verferies** — a list of lists of :class:`Verfer` instances,
              one inner list per ingested establishment event, in order.

        Raises:
            ValueError: If ``iridx > len(secrecies)``, or if key material
                for the derived prefix already exists in the database, or if
                any database write fails.
        """
        if iridx > len(secrecies):
            raise ValueError(f"Initial ridx={iridx} beyond last secrecy.")

        # configure parameters for creating new keys after ingested sequence
        if rooted and salt is None:  # use root salt instead of random salt
            salt = self.salt

        if rooted and tier is None:  # use root tier as default
            tier = self.tier

        pidx = self.pidx  # get next pidx

        creator = Creatory(algo=algo).make(salt=salt, stem=stem, tier=tier)
        ipre = ""
        dt = ""  # empty for incept of old
        pubs = []
        ridx = 0
        kidx = 0

        verferies = []  # list of lists of verfers
        first = True
        secrecies = deque(secrecies)
        while secrecies:
            csecrets = secrecies.popleft()  # current
            csigners = [Signer(qb64=secret, transferable=transferable)
                                                      for secret in csecrets]
            csize = len(csigners)
            verferies.append([signer.verfer for signer in csigners])

            if first:
                # Secret to encrypt here
                pp = PrePrm(pidx=pidx,
                            algo=algo,
                            salt=(creator.salt if not self.encrypter
                                  else self.encrypter.encrypt(ser=creator.salt,
                                        code=MtrDex.X25519_Cipher_Salt).qb64),
                            stem=creator.stem,
                            tier=creator.tier)
                pre = csigners[0].verfer.qb64b
                ipre = csigners[0].verfer.qb64
                if not self.ks.pres.put(pre, val=Prefixer(qb64=pre)):
                    raise ValueError("Already incepted pre={}.".format(pre.decode("utf-8")))

                if not self.ks.prms.put(pre, val=pp):
                    raise ValueError("Already incepted prm for pre={}.".format(pre.decode("utf-8")))

                self.pidx = pidx + 1  # increment so unique
                first = False

            for signer in csigners:  # store secrets (private key val keyed by public key)
                self.ks.pris.put(keys=signer.verfer.qb64b, val=signer,
                                 encrypter=self.encrypter)

            pubs = [signer.verfer.qb64 for signer in csigners]
            self.ks.pubs.put(riKey(pre, ri=ridx), val=PubSet(pubs=pubs))

            dt = nowIso8601()
            if ridx == max(iridx - 1, 0):  # setup ps.old at this ridx
                if iridx == 0:
                    old = PubLot()  # defaults ok
                else:
                    osigners = csigners
                    osith = "{:x}".format(max(1, math.ceil(len(osigners) / 2)))
                    ost = Tholder(sith=osith).sith
                    old=PubLot(pubs=pubs, ridx=ridx, kidx=kidx, dt=dt)
                ps = PreSit(old=old)  # .new and .nxt are default
                if not self.ks.sits.pin(pre, val=ps):
                    raise ValueError("Problem updating pubsit db for pre={}.".format(pre))

            if ridx == iridx:  # setup ps.new at this ridx
                if (ps := self.ks.sits.get(pre)) is None:
                    raise ValueError("Attempt to rotate nonexistent pre={}.".format(pre))
                new=PubLot(pubs=pubs, ridx=ridx, kidx=kidx, dt=dt)
                ps.new = new
                if not self.ks.sits.pin(pre, val=ps):
                    raise ValueError("Problem updating pubsit db for pre={}.".format(pre))

            if ridx == iridx + 1:  # set up ps.nxt at this ridx
                if (ps := self.ks.sits.get(pre)) is None:
                    raise ValueError("Attempt to rotate nonexistent pre={}.".format(pre))
                nsigners = csigners
                nxt=PubLot(pubs=pubs, ridx=ridx, kidx=kidx, dt=dt)
                ps.nxt = nxt
                if not self.ks.sits.pin(pre, val=ps):
                    raise ValueError("Problem updating pubsit db for pre={}.".format(pre))

            ridx += 1  # next ridx
            kidx += csize  # next kidx

        # create nxt signers after ingested signers
        nsigners = creator.create(count=ncount, code=ncode,
                                  pidx=pidx, ridx=ridx, kidx=kidx,
                                  transferable=transferable, temp=temp)


        for signer in nsigners:  # store secrets (private key val keyed by public key)
            self.ks.pris.put(keys=signer.verfer.qb64b, val=signer)

        pubs = [signer.verfer.qb64 for signer in nsigners]
        self.ks.pubs.put(riKey(pre, ri=ridx), val=PubSet(pubs=pubs))

        if ridx == iridx + 1:  # want to set up ps.next at this ridx
            dt = nowIso8601()
            if (ps := self.ks.sits.get(pre)) is None:
                raise ValueError("Attempt to rotate nonexistent pre={}.".format(pre))
            nxt=PubLot(pubs=pubs, ridx=ridx, kidx=kidx, dt=dt)
            ps.nxt = nxt
            if not self.ks.sits.pin(pre, val=ps):
                raise ValueError("Problem updating pubsit db for pre={}.".format(pre))

        return (ipre, verferies) #


    def replay(self, pre, dcode=MtrDex.Blake3_256, advance=True, erase=True):
        """Replay the next establishment event's key set from pre-stored public keys.

        Retrieves the public key set stored at the next rotation index from
        the ``ks.pubs`` database and, when ``advance=True``, advances the
        :class:`PreSit` so that:

        * The current ``ps.new`` is moved to ``ps.old``.
        * The current ``ps.nxt`` is moved to ``ps.new``.
        * The public key set at the incremented rotation index is loaded as
          the new ``ps.nxt``.

        An :exc:`IndexError` is raised when no ``pubs`` entry exists at
        ``ps.new.ridx + 1`` after the advance, signalling that all
        pre-stored establishment events have been replayed.

        When ``advance=False``, the current ``ps.new`` is returned without
        any state update, providing a read-only view of the active key set.

        Args:
            pre (str): Fully qualified qb64 identifier prefix to replay.
            dcode (str): Derivation code for computing next key digests.
                Defaults to ``MtrDex.Blake3_256``.
            advance (bool): When ``True`` advance the :class:`PreSit` state
                and persist the update.  When ``False`` return the current
                active key set without modifying state.
                Defaults to ``True``.
            erase (bool): When ``True`` and ``advance=True``, delete the
                private keys of the pre-advance ``ps.old`` set from
                ``ks.pris``. Defaults to ``True``.

        Returns:
            tuple[list[Verfer], list[Diger]]: A two-element tuple:

            * **verfers** — one :class:`Verfer` per key in the current
              active (``ps.new``) signing key set after any advance;
              ``verfer.qb64`` is the public key.
            * **digers** — one :class:`Diger` per key in the pre-committed
              next (``ps.nxt``) key set, computed as the digest of each
              public key's bytes.

        Raises:
            ValueError: If ``pre`` has no stored :class:`PrePrm` or
                :class:`PreSit`, if a private key is missing from the
                database, or if the :class:`PreSit` update fails.
            IndexError: If ``advance=True`` and the ``ks.pubs`` database
                has no entry at ``ps.new.ridx + 1`` (end of the pre-stored
                replay sequence).
            DecryptError: If an ``aeid`` is configured but no decrypter is
                available.
        """
        if (pp := self.ks.prms.get(pre)) is None:
            raise ValueError("Attempt to replay nonexistent pre={}.".format(pre))

        if (ps := self.ks.sits.get(pre)) is None:
            raise ValueError("Attempt to replay nonexistent pre={}.".format(pre))


        if advance:
            old = ps.old  # save prior old so can clean out if rotate successful
            ps.old = ps.new  # move prior new to old so save previous one step
            ps.new = ps.nxt  # move prior nxt to new which new is now current signer
            ridx = ps.new.ridx
            kidx = ps.new.kidx
            csize = len(ps.new.pubs)

            # Usually when next keys are null then aid is effectively non-transferable
            # but when replaying injected keys reaching null next pub keys or
            # equivalently default empty is the sign that we have reached the
            # end of the replay so need to raise an IndexError
            if not (pubset := self.ks.pubs.get(riKey(pre, ridx+1))):
                # empty nxt public keys so end of replay
                raise IndexError(f"Invalid replay attempt of pre={pre} at "
                                 f"ridx={ridx}.")
            pubs = pubset.pubs  # create nxt from pubs
            dt = nowIso8601()
            nxt=PubLot(pubs=pubs, ridx=ridx+1, kidx=kidx+csize, dt=dt)
            ps.nxt = nxt


        verfers = []  # assign verfers from current new was prior nxt
        for pub in ps.new.pubs:
            if self.aeid and not self.decrypter:  # maybe should rethink this
                raise DecryptError("Unauthorized decryption attempt. "
                                          "Aeid but no decrypter.")

            if ((signer := self.ks.pris.get(pub.encode("utf-8"),
                                           decrypter=self.decrypter)) is None):
                raise ValueError("Missing prikey in db for pubkey={}".format(pub))
            verfers.append(signer.verfer)

        digers = [Diger(ser=pub.encode("utf-8"), code=dcode)
                    for pub in ps.nxt.pubs]

        if advance:
            if not self.ks.sits.pin(pre, val=ps):
                raise ValueError("Problem updating pubsit db for pre={}.".format(pre))
            if erase:
                for pub in old.pubs:  # remove prior old prikeys not current old
                    self.ks.pris.rem(pub)

        return (verfers, digers)


class ManagerDoer(doing.Doer):
    """Doer that defers and triggers :class:`Manager` initialization.

    Calls :meth:`Manager.setup` on enter if the manager has not yet been
    initialized (i.e. :attr:`Manager.inited` is ``False``).  The exit
    handler is a no-op because the :class:`Manager` does not own the
    underlying :class:`Keeper` database lifecycle (that is managed by a
    separate :class:`KeeperDoer`).

    Attributes:
        manager (Manager): The :class:`Manager` instance whose
            initialization this doer triggers.

    Inherited Attributes:
        done (bool): Completion state. ``True`` means the doer finished
            normally; ``False`` means it is still running, was closed, or
            was aborted.

        tyme (float): Relative cycle time supplied by the injected
            :class:`Tymist`.

        tymth (callable): Closure that returns the associated
            :class:`Tymist`'s ``.tyme`` when called.

        tock (float): Desired seconds between recur calls. ``0`` means run
            as soon as possible.
    """

    def __init__(self, manager, **kwa):
        """Initialize the ManagerDoer.

        Args:
            manager (Manager): The :class:`Manager` instance to initialize
                on enter.
            **kwa: Additional keyword arguments forwarded to
                :class:`doing.Doer.__init__`.
        """
        super(ManagerDoer, self).__init__(**kwa)
        self.manager = manager


    def enter(self, *, temp=None):
        """Call :meth:`Manager.setup` if the manager is not yet initialized.

        Called automatically when the doer enters its execution context.
        Passes the keyword arguments captured in ``manager._inits`` at
        construction time to :meth:`Manager.setup`.

        Args:
            temp (bool | None): Unused; present for interface compatibility.
        """
        if not self.manager.inited:
            self.manager.setup(**self.manager._inits)


    def exit(self):
        """No-op exit handler."""
        pass
