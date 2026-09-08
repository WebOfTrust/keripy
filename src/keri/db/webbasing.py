# -*- encoding: utf-8 -*-
"""
keri.db.webbasing module

Browser-safe plain-value DBer backed by PyScript storage.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

from hio.base import doing
from hio.help import ogler

from keri import __version__

from ..recording import (KeyStateRecord, EventSourceRecord,
                         HabitatRecord, OobiRecord, EndpointRecord,
                         LocationRecord, ObservedRecord,
                         CacheTypeRecord, TxnMsgCacheRecord,
                         MsgCacheRecord, WellKnownAuthN,
                         TopicsRecord)

from ..kering import Version

from .webdbing import WebDBer

from .basebasing import BaserBase

logger = ogler.getLogger()


class WebBaser(WebDBer, BaserBase):
    def __init__(self, name="main", reopen=False, temp=False, **kwa):
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
            reopen (bool): True is unsupported; use await reopen().


        """
        if reopen:
            raise RuntimeError("WebBaser uses async open; use await reopen().")

        SubDbNames = ["aess.", "bsss.", "bsqs.", "ccigs.", "cdel.", "cfld.", "chas.",
            "cgms.", "coobi.", "cons.", "ctyp.", "dees.", "dels.", "dpwe.", "dpub.",
            "dtss.", "dune.", "eans.", "ecigs.", "ends.", "eoobi.", "epath.", "epse.",
            "epsd.", "erpy.", "esigs.", "esrs.", "essrs.", "exns.", "enst.", "evts.", "fels.", "fons.",
            "frcs.", "gdee.", "gdwe.", "gpse.", "habs.", "hbys.", "iimgs.", "icigs.",
            "ifld.", "imgs.", "kels.", "kdts.", "knas.", "ksns.", "lans.", "ldes.",
            "locs.", "maids.", "meids.", "mfes.", "mfa.", "migs.", "moobi.", "msgc.",
            "names.", "obvs.", "oobis.", "ooes.", "pdes.", "pmkm.", "pmks.", "pmsk.",
            "pses.", "ptds.", "pwes.", "qnfs.", "rcts.", "reps.", "rpes.", "rmfa.",
            "roobi.", "rpys.", "scgs.", "schema.", "sdts.", "sids.", "sigs.", "sscs.",
            "ssts.", "stts.", "tdcs.", "tmsc.", "tmqs.", "trqs.", "tsgs.", "udes.",
            "ures.", "uwes.", "vrcs.", "vres.", "vers.", "wigs.", "wits.", "wkas.",
            "witm.", "woobi.", "wwas.", "xdt."
        ]
        self.SubDbNames = SubDbNames

        self.name = name
        self._storageName = f"__keripy_temp__:{name}:{uuid4().hex}" if temp else name
        self._version = None
        self.opened = False

        self.temp = temp
        self._closeTask = None
        self._clearPending = False
        self._cleanLock = asyncio.Lock()

        BaserBase.__init__(self)

    async def reopen(self, clear=False, storageOpener=None):
        """Open or re-open the WebBaser backing store.

        Loads the baser's declared SubDbs, adopts their WebDBer state directly,
        binds all SubDbs to this WebBaser, then rebuilds
        in-memory state (kevers, escrows) via ``reload()``.

        This method must be awaited because browser storage operations are
        asynchronous.  After calling ``reopen()`` the WebBaser is fully
        operational and ready for reads, writes, and flushes. Calling
        ``reopen()`` on an already-open baser first closes it durably.

        Parameters:
            clear (bool): When True, all existing persisted data for this
                baser (across all SubDbs) is cleared before loading.
            storageOpener (callable | None): Optional async factory that
                returns a storage handle for a given namespace.  Overrides
                the default PyScript opener.  Used to inject
                FakeStorageBackend in CPython tests.
        """
        from . import koming, subing
        from ..core import coring, indexing

        if self._closeTask is not None or self.opened:
            await self.aclose()

        if storageOpener is not None:
            self._storageOpener = storageOpener
        opener = getattr(self, "_storageOpener", None)

        try:
            opened = await WebDBer.open(
                name=self._storageName if self.temp else self.name,
                stores=self.SubDbNames,
                clear=clear,
                storageOpener=opener,
            )
        except RuntimeError as e:
            if opener is None:
                raise RuntimeError(
                    "No storage opener available. "
                    "Provide storageOpener=FakeStorageBackend.open in CPython, "
                    "or run under PyScript for IndexedDB."
                ) from e
            raise

        fresh = all(not store.items and not store.flags_persisted
                    for store in opened._stores.values())
        WebDBer.__init__(self, name=self.name, stores=opened._stores)
        if fresh:
            self.version = __version__
            await self.flush()
        _before = set(self.__dict__)
        self.evts = subing.SerderSuber(db=self, subkey='evts.')
        self.fels = subing.OnSuber(db=self, subkey='fels.')
        self.kels = subing.OnIoSetSuber(db=self, subkey='kels.')
        self.dtss = subing.CesrSuber(db=self, subkey='dtss.', klas=coring.Dater)
        self.aess = subing.CatCesrSuber(db=self, subkey='aess.',
                                        klas=(coring.Number, coring.Diger))
        self.sigs = subing.CesrIoSetSuber(db=self, subkey='sigs.',
                                        klas=(indexing.Siger))
        self.wigs = subing.CesrIoSetSuber(db=self, subkey='wigs.', klas=indexing.Siger)
        self.rcts = subing.CatCesrIoSetSuber(db=self, subkey="rcts.",
                                             klas=(coring.Prefixer, coring.Cigar))
        self.ures = subing.CatCesrIoSetSuber(db=self, subkey='ures.',
                                             klas=(coring.Diger, coring.Prefixer, coring.Cigar))
        self.vrcs = subing.CesrIoSetSuber(db=self,
                                          subkey='vrcs.',
                                          klas=indexing.Siger)
        self.vres = subing.CatCesrIoSetSuber(db=self, subkey='vres.',
                             klas=(coring.Diger, coring.Prefixer, coring.Number, coring.Diger, indexing.Siger))
        self.pses = subing.OnIoSetSuber(db=self, subkey='pses.')
        self.pwes = subing.OnIoSetSuber(db=self, subkey='pwes.')
        self.pdes = subing.OnIoSetSuber(db=self, subkey='pdes.')
        self.udes = subing.CatCesrSuber(db=self, subkey='udes.', klas=(coring.Number, coring.Diger))
        self.uwes = subing.B64OnIoSetSuber(db=self, subkey='uwes.')
        self.ooes = subing.OnIoSetSuber(db=self, subkey='ooes.')
        self.dels = subing.OnIoSetSuber(db=self, subkey='dels.')
        self.ldes = subing.OnIoSetSuber(db=self, subkey='ldes.')
        self.qnfs = subing.IoSetSuber(db=self, subkey="qnfs.")

        # events as ordered by first seen ordinals
        self.fons = subing.CesrSuber(db=self, subkey='fons.', klas=coring.Number)

        self.migs = subing.CesrSuber(db=self, subkey="migs.", klas=coring.Dater)
        self.vers = subing.Suber(db=self, subkey="vers.")

        # event source local (protected) or non-local (remote not protected)
        self.esrs = koming.Komer(db=self,
                                   klas=EventSourceRecord,
                                   subkey='esrs.')

        # misfit escrows whose processing may change the .esrs event source record
        self.misfits = subing.OnIoSetSuber(db=self, subkey='mfes.')

        # delegable events escrows. events with local delegator that need approval
        self.delegables = subing.IoSetSuber(db=self, subkey='dees.')

        # Kever state made of KeyStateRecord key states
        self.states = koming.Komer(db=self,
                                   klas=KeyStateRecord,
                                   subkey='stts.')

        self.wits = subing.CesrIoSetSuber(db=self, subkey="wits.", klas=coring.Prefixer)

        # habitat application state keyed by habitat name, includes prefix
        self.habs = koming.Komer(db=self,
                                 subkey='habs.',
                                 klas=HabitatRecord, )
        # habitat name database mapping (domain,name) as key to Prefixer
        self.names = subing.Suber(db=self, subkey='names.', sep="^")

        # SAD support datetime stamps and signatures indexed and not-indexed
        # all sad  sdts (sad datetime serializations) maps said to date-time
        self.sdts = subing.CesrSuber(db=self, subkey='sdts.', klas=coring.Dater)

        # all sad tsgs (sad indexed signature serializations) maps SAD quadkeys
        # given by quadruple (diger.qb64, prefixer.qb64, seqner.q64, diger.qb64)
        #  of reply and trans signer's key state est evt to val Siger for each
        # signature.
        self.tsgs = subing.CesrIoSetSuber(db=self, subkey='tsgs.', klas=indexing.Siger)

        # all sad scgs  (sad non-indexed signature serializations) maps SAD SAID
        # to couple (Verfer, Cigar) of nontrans signer of signature in Cigar
        # nontrans qb64 of Prefixer is same as Verfer
        self.scgs = subing.CatCesrIoSetSuber(db=self, subkey='scgs.',
                                             klas=(coring.Verfer, coring.Cigar))

        # all reply messages. Maps reply said to serialization. Replys are
        # versioned sads ( with version string) so use Serder to deserialize and
        # use  .sdts, .tsgs, and .scgs for datetimes and signatures
        # TODO: clean
        self.rpys = subing.SerderSuber(db=self, subkey='rpys.')

        # all reply escrows indices of partially signed reply messages. Maps
        # route in reply to single (Diger,)  of escrowed reply.
        # Routes such as /end/role  /loc/schema
        self.rpes = subing.CesrIoSetSuber(db=self, subkey='rpes.',
                                          klas=coring.Diger)

        # auth AuthN/AuthZ by controller at cid of endpoint provider at eid
        # maps key=cid.role.eid to val=diger of end reply
        self.eans = subing.CesrSuber(db=self, subkey='eans.', klas=coring.Diger)

        # auth AuthN/AuthZ by endpoint provider at eid of location at scheme url
        # maps key=cid.role.eid to val=diger of end reply
        self.lans = subing.CesrSuber(db=self, subkey='lans.', klas=coring.Diger)

        # service endpoint identifier (eid) auths keyed by controller cid.role.eid
        # data extracted from reply /end/role/add or /end/role/cut
        self.ends = koming.Komer(db=self, subkey='ends.',
                                 klas=EndpointRecord, )

        # service endpoint locations keyed by eid.scheme  (endpoint identifier)
        # data extracted from reply loc
        self.locs = koming.Komer(db=self,
                                 subkey='locs.',
                                 klas=LocationRecord, )
        # observed oids by watcher by cid.aid.oid  (endpoint identifier)
        # data extracted from reply loc
        self.obvs = koming.Komer(db=self,
                                 subkey='obvs.',
                                 klas=ObservedRecord, )

        # index of last retrieved message from witness mailbox
        self.tops = koming.Komer(db=self,
                                 subkey='witm.',
                                 klas=TopicsRecord, )

        # group partial signature escrow
        self.gpse = subing.CatCesrIoSetSuber(db=self, subkey='gpse.',
                                             klas=(coring.Number, coring.Diger))

        # group delegate escrow
        self.gdee = subing.CatCesrIoSetSuber(db=self, subkey='gdee.',
                                             klas=(coring.Number, coring.Diger))

        # group partial witness escrow
        self.gpwe = subing.CatCesrIoSetSuber(db=self, subkey='gdwe.',
                                             klas=(coring.Number, coring.Diger))

        # completed group multisig
        self.cgms = subing.CesrSuber(db=self, subkey='cgms.',
                                     klas=coring.Diger)

        # exchange message partial signature escrow
        self.epse = subing.SerderSuber(db=self, subkey="epse.")

        # exchange message PS escrow date time of message
        self.epsd = subing.CesrSuber(db=self, subkey="epsd.",
                                     klas=coring.Dater)

        # exchange messages
        self.exns = subing.SerderSuber(db=self, subkey="exns.")

        # Forward pointer to a provided reply message
        self.erpy = subing.CesrSuber(db=self, subkey="erpy.", klas=coring.Saider)

        # exchange message signatures
        self.esigs = subing.CesrIoSetSuber(db=self, subkey='esigs.', klas=indexing.Siger)

        # exchange message signatures
        self.ecigs = subing.CatCesrIoSetSuber(db=self, subkey='ecigs.',
                                              klas=(coring.Verfer, coring.Cigar))

        # exchange pathed attachments
        self.epath = subing.IoSetSuber(db=self, subkey="epath.")

        # exchange nested child substreams
        self.enst = subing.IoSetSuber(db=self, subkey="enst.")

        self.essrs = subing.CesrIoSetSuber(db=self, subkey="essrs.", klas=coring.Texter)

        # accepted signed 12-word challenge response exn messages keys by prefix of signer
        self.chas = subing.CesrIoSetSuber(db=self, subkey='chas.', klas=coring.Diger)

        # successfull signed 12-word challenge response exn messages keys by prefix of signer
        self.reps = subing.CesrIoSetSuber(db=self, subkey='reps.', klas=coring.Diger)

        # authorzied well known OOBIs
        self.wkas = koming.IoSetKomer(db=self, subkey='wkas.', klas=WellKnownAuthN)

        # KSN support datetime stamps and signatures indexed and not-indexed
        # all ksn  kdts (key state datetime serializations) maps said to date-time
        self.kdts = subing.CesrSuber(db=self, subkey='kdts.', klas=coring.Dater)

        # all key state messages. Maps key state said to serialization. ksns are
        # KeyStateRecords so use ._asdict or ._asjson as appropriate
        # use  .kdts, .ksgs, and .kcgs for datetimes and signatures
        self.ksns = koming.Komer(db=self,
                                klas=KeyStateRecord,
                                subkey='ksns.')

        # key state SAID database for successfully saved key state notices
        # maps key=(prefix, aid) to val=said of key state
        self.knas = subing.CesrSuber(db=self, subkey='knas.', klas=coring.Diger)

        # Watcher watched SAID database for successfully saved watched AIDs for a watcher
        # maps key=(cid, aid, oid) to val=said of rpy message
        self.wwas = subing.CesrSuber(db=self, subkey='wwas.', klas=coring.Diger)

        # config loaded oobis to be processed asynchronously, keyed by oobi URL
        self.oobis = koming.Komer(db=self,
                                  subkey='oobis.',
                                  klas=OobiRecord,
                                  sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # escrow OOBIs that failed to load, retriable, keyed by oobi URL
        self.eoobi = koming.Komer(db=self,
                                  subkey='eoobi.',
                                  klas=OobiRecord,
                                  sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # OOBIs with outstand client requests.
        self.coobi = koming.Komer(db=self,
                                  subkey='coobi.',
                                  klas=OobiRecord,
                                  sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # Resolved OOBIs (those that have been processed successfully for this database.
        self.roobi = koming.Komer(db=self,
                                  subkey='roobi.',
                                  klas=OobiRecord,
                                  sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # Well known OOBIs that are to be used for mfa against a resolved OOBI.
        self.woobi = koming.Komer(db=self,
                                  subkey='woobi.',
                                  klas=OobiRecord,
                                  sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # Well known OOBIs that are to be used for mfa against a resolved OOBI.
        self.moobi = koming.Komer(db=self,
                                  subkey='moobi.',
                                  klas=OobiRecord,
                                  sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # Multifactor well known OOBI auth records to process.  Keys by controller URL
        self.mfa = koming.Komer(db=self,
                                subkey='mfa.',
                                klas=OobiRecord,
                                sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # Resolved multifactor well known OOBI auth records.  Keys by controller URL
        self.rmfa = koming.Komer(db=self,
                                 subkey='rmfa.',
                                 klas=OobiRecord,
                                 sep=">")  # Use seperator not allowed in URLs so no splitting occurs.

        # JSON schema SADs keys by the SAID
        self.schema = subing.SchemerSuber(db=self,
                                          subkey='schema.')

        # Field values for contact information for remote identifiers.  Keyed by prefix/field
        self.cfld = subing.Suber(db=self,
                                 subkey="cfld.")

        # Global settings for the Habery environment
        self.hbys = subing.Suber(db=self, subkey='hbys.')

        # Signed contact data, keys by prefix
        self.cons = subing.Suber(db=self,
                                 subkey="cons.")

        # Transferable signatures on contact data
        self.ccigs = subing.CesrSuber(db=self, subkey='ccigs.', klas=coring.Cigar)

        # Blinded media for contact information for remote identifiers.
        # CatCesrSuber with TypeMedia format: (Noncer=SAID, Noncer=UUID, Labeler=MIME, Texter=data)
        self.imgs = subing.CatCesrSuber(db=self, subkey='imgs.',
                                         klas=(coring.Noncer, coring.Noncer,
                                               coring.Labeler, coring.Texter))

        # Field values for identifier information for local identifiers. Keyed by prefix/field
        self.ifld = subing.Suber(db=self,
                                 subkey="ifld.")

        # Signed identifier data, keys by prefix
        self.sids = subing.Suber(db=self,
                                  subkey="sids.")

        # Transferable signatures on identifier data
        self.icigs = subing.CesrSuber(db=self, subkey='icigs.', klas=coring.Cigar)

        # Blinded media for identifier information for local identifiers.
        # CatCesrSuber with TypeMedia format: (Noncer=SAID, Noncer=UUID, Labeler=MIME, Texter=data)
        self.iimgs = subing.CatCesrSuber(db=self, subkey='iimgs.',
                                          klas=(coring.Noncer, coring.Noncer,
                                                coring.Labeler, coring.Texter))

        # Delegation escrow dbs #
        # delegated partial witness escrow
        self.dpwe = subing.SerderSuber(db=self, subkey='dpwe.')

        # delegated unanchored escrow
        self.dune = subing.SerderSuber(db=self, subkey='dune.')

        # delegate publication escrow for sending delegator info to my witnesses
        self.dpub = subing.SerderSuber(db=self, subkey='dpub.')

        # completed group delegated AIDs
        self.cdel = subing.CesrOnSuber(db=self, subkey='cdel.',
                                     klas=coring.Diger)

        # multisig sig embed payload SAID mapped to containing exn messages across group multisig participants
        self.meids = subing.CesrIoSetSuber(db=self, subkey="meids.", klas=coring.Diger)

        # multisig sig embed payload SAID mapped to group multisig participants AIDs
        self.maids = subing.CesrIoSetSuber(db=self, subkey="maids.", klas=coring.Prefixer)

        # KRAM cache type — key: expression string, value: drift and lag params
        self.kramCTYP = koming.Komer(db=self, subkey='ctyp.',
                                 klas=CacheTypeRecord)

        # KRAM message cache — key: (AID, MID), value: msg datetime, drift, lags
        self.kramMSGC = koming.Komer(db=self, subkey='msgc.',
                                 klas=MsgCacheRecord)

        # KRAM transactioned message cache — key: (AID, XID, MID), value: datetimes, drift, lags
        self.kramTMSC = koming.Komer(db=self, subkey='tmsc.',
                                 klas=TxnMsgCacheRecord)

        self.kramXDT = subing.CesrSuber(db=self, subkey='xdt.',
                                       klas=coring.Dater)

        # KRAM partially signed multi-key message key (AID.MID) mapped to associated message (SerderKERI)
        self.kramPMKM = subing.SerderSuber(db=self, subkey='pmkm.')

        # KRAM partially signed multi-key signature key (AID.MID) mapped to associated signatures
        self.kramPMKS = subing.CesrIoSetSuber(db=self, subkey='pmks.', klas=indexing.Siger)

        # KRAM partially signed multi-key sender key state key (AID.MID) mapped to SN and event SAID
        self.kramPMSK = subing.CatCesrSuber(db=self, subkey='pmsk.', klas=(coring.Number, coring.Diger))

        # KRAM partially signed multi-key non-authenticator attachments

        # trqs: trans receipt quadruples (prefixer, number, diger, siger)
        self.kramTRQS = subing.CatCesrIoSetSuber(db=self, subkey='trqs.',
                                                  klas=(coring.Prefixer, coring.Number,
                                                        coring.Diger, indexing.Siger))

        # tsgs: trans last sig groups (prefixer, number, diger, siger) — stored per-siger
        self.kramTSGS = subing.CatCesrIoSetSuber(db=self, subkey='tsgs.',
                                                  klas=(coring.Prefixer, coring.Number,
                                                        coring.Diger, indexing.Siger))

        # sscs: first seen seal couples (number, diger) issuing or delegating
        self.kramSSCS = subing.CatCesrIoSetSuber(db=self, subkey='sscs.',
                                                  klas=(coring.Number, coring.Diger))

        # ssts: source seal triples (prefixer, number, diger) issued or delegated
        self.kramSSTS = subing.CatCesrIoSetSuber(db=self, subkey='ssts.',
                                                  klas=(coring.Prefixer, coring.Number,
                                                        coring.Diger))

        # frcs: first seen replay couples (number, dater)
        self.kramFRCS = subing.CatCesrIoSetSuber(db=self, subkey='frcs.',
                                                  klas=(coring.Number, coring.Dater))

        # tdcs: typed digest seal couples (verser, diger)
        self.kramTDCS = subing.CatCesrIoSetSuber(db=self, subkey='tdcs.',
                                                  klas=(coring.Verser, coring.Diger))

        # ptds: pathed streams (raw bytes)
        self.kramPTDS = subing.IoSetSuber(db=self, subkey='ptds.')

        # bsqs: blind state quadruples (diger, noncer, noncer, labeler)
        self.kramBSQS = subing.CatCesrIoSetSuber(db=self, subkey='bsqs.',
                                                  klas=(coring.Diger, coring.Noncer,
                                                        coring.Noncer, coring.Labeler))

        # bsss: bound state sextuples (diger, noncer, noncer, labeler, number, noncer)
        self.kramBSSS = subing.CatCesrIoSetSuber(db=self, subkey='bsss.',
                                                  klas=(coring.Diger, coring.Noncer,
                                                        coring.Noncer, coring.Labeler,
                                                        coring.Number, coring.Noncer))

        # tmqs: type media quadruples (diger, noncer, labeler, texter)
        self.kramTMQS = subing.CatCesrIoSetSuber(db=self, subkey='tmqs.',
                                                  klas=(coring.Diger, coring.Noncer,
                                                        coring.Labeler, coring.Texter))

        # Every attribute added above is a Suber or Komer.  Record their
        # names so close()/aclose() can null them out to prevent silent
        # writes to orphaned SubDb objects.
        self._subdb_names = set(self.__dict__) - _before
        self.opened = True
        self.reload()


    def close(self, *, clear: bool = False):
        """Synchronous close. Safe to call from hio Doer.exit() and Habery.close().

        Outside a running event loop this method runs :meth:`aclose` to
        completion. Inside a running event loop it schedules and tracks the
        async close so the caller is not blocked.

        A running-loop close is not durable when this method returns. Async
        callers that need a durable close must await :meth:`aclose`.

        When ``clear=True`` (or ``self.temp is True``), the async close empties
        each SubDb and persists the cleared state.

        If the baser is not open the method returns immediately.

        Note:
            After the async close completes, all Suber/Komer attributes (e.g.
            ``self.oobis``) are deleted. Any attempt to access them will raise
            ``AttributeError``, making accidental post-close usage fail
            loudly instead of silently writing to an orphaned in-memory
            SubDb.  The attributes are rebound on ``reopen()``.

        Parameters:
            clear (bool): When True, the backing storage for this WebBaser
                is cleared.  When False (default), stored state is preserved
                for future ``reopen()`` calls.
        """
        if self._closeTask is None and not self.opened:
            return

        self._clearPending = self._clearPending or clear or self.temp
        if self._closeTask is not None:
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.aclose())
        else:
            self.opened = False
            self._closeTask = loop.create_task(self.aclose())


    async def aclose(self, *, clear: bool = False):
        """Async close with guaranteed flush — use when the caller can ``await``.

        Flushes all pending in-memory writes to backing browser storage and
        waits for the flush to complete before clearing internal references.
        This is the preferred close path in any ``async`` context (tests,
        wallet ``AsyncRecurDoer.recur_async()`` shutdown, etc.) because the
        caller can be certain that all data has been persisted when the method
        returns.

        When ``clear=True`` (or ``self.temp is True``), each SubDb's in-memory
        items are emptied and marked dirty before flushing, so the cleared
        state is what gets persisted.

        For sync callers (hio Doer.exit(), Habery.close(), openHby() context
        manager) use :meth:`close` instead.

        If the baser is not open the method returns immediately.

        Note:
            After close, all Suber/Komer attributes (e.g. ``self.oobis``)
            are deleted.  Any attempt to access them will raise
            ``AttributeError``, making accidental post-close usage fail
            loudly instead of silently writing to an orphaned in-memory
            SubDb.  The attributes are rebound on ``reopen()``.

        Parameters:
            clear (bool): When True the backing storage for this WebBaser
                is cleared.  When False (default) stored state is preserved
                for future ``reopen()`` calls.
        """
        task = self._closeTask
        if task is None and not self.opened:
            return

        if clear or self.temp:
            self._clearPending = True

        if task is not None and task is not asyncio.current_task():
            try:
                await task
            except asyncio.CancelledError:
                self.opened = True
                raise
            finally:
                if self._closeTask is task:
                    self._closeTask = None
            return

        clearApplied = self._clearPending
        if clearApplied:
            self.clear()
            self.version = __version__

        try:
            await self.flush()
            if self._clearPending and not clearApplied:
                self.clear()
                self.version = __version__
                await self.flush()
        except asyncio.CancelledError:
            if task is asyncio.current_task():
                self.opened = True
            raise
        except Exception:
            if task is asyncio.current_task():
                self.opened = True
            raise

        WebDBer.close(self)
        self.env = None
        self.opened = False
        self._clearPending = False
        if task is asyncio.current_task() and self._closeTask is task:
            self._closeTask = None

        # Remove all Suber/Komer attributes so post-close writes raise
        # AttributeError instead of silently going to an orphaned SubDb.
        for name in getattr(self, '_subdb_names', ()):
            try:
                delattr(self, name)
            except AttributeError:
                pass

    def clear(self):
        """Clear browser records and retain the current schema version."""
        WebDBer.clear(self)
        self.version = __version__


    def reload(self):
        """Rebuild the browser Kever caches from the active stores."""
        self.prefixes.clear()
        self.groups.clear()
        self._kevers.clear()
        BaserBase.reload(self)


    async def clean(self, gvrsn=Version, *, version=None):
        """Clean database by replaying events into a fresh clone and swapping data.

        As with native Baser.clean, KRAM replay caches and pending messages are
        not preserved. Cleaning KRAM state requires a separate repair policy.
        """
        if version is not None:
            gvrsn = version

        async with self._cleanLock:
            from hashlib import sha256

            from ..core import parsing
            from ..core.eventing import Kevery

            name = self._storageName if self.temp else self.name
            digest = sha256(name.encode("utf-8")).hexdigest()
            copy = WebBaser(name=f"__keripy_clean__:{digest}")
            await copy.reopen(clear=True,
                              storageOpener=getattr(self, "_storageOpener", None))
            try:
                kvy = Kevery(db=copy)
                psr = parsing.Parser(kvy=kvy, version=gvrsn)
                for msg in self.cloneAllPreIter(gvrsn=gvrsn):
                    psr.parseOne(ims=msg)

                unsecured = [
                    "hbys", "schema", "states", "rpys", "eans", "tops", "cgms",
                    "exns", "erpy", "kdts", "ksns", "knas", "oobis", "roobi",
                    "woobi", "moobi", "mfa", "rmfa", "cfld", "cons", "ccigs",
                    "cdel", "migs", "ifld", "sids", "icigs",
                ]
                for name in unsecured:
                    srcdb = getattr(self, name, None)
                    cpydb = getattr(copy, name, None)
                    if srcdb is None or cpydb is None:
                        continue
                    for keys, val in srcdb.getTopItemIter():
                        cpydb.put(keys=keys, val=val)

                sets = [
                    "esigs", "ecigs", "epath", "enst", "chas", "reps", "wkas",
                    "meids", "maids",
                ]
                for name in sets:
                    srcdb = getattr(self, name, None)
                    cpydb = getattr(copy, name, None)
                    if srcdb is None or cpydb is None:
                        continue
                    for keys, val in srcdb.getTopItemIter():
                        cpydb.add(keys=keys, val=val)

                for keys, val in self.imgs.getTopItemIter():
                    copy.imgs.pin(keys=keys, val=val)
                for keys, val in self.iimgs.getTopItemIter():
                    copy.iimgs.pin(keys=keys, val=val)

                for keys, val in self.habs.getTopItemIter():
                    if val.hid in copy.kevers:
                        copy.habs.put(keys=keys, val=val)
                        ns = "" if val.domain is None else val.domain
                        copy.names.put(keys=(ns, val.name), val=val.hid)
                        copy.prefixes.add(val.hid)
                        if val.mid:
                            copy.groups.add(val.hid)

                for (cid, role, eid), val in self.ends.getTopItemIter():
                    exists = False
                    for scheme in ("https", "http", "tcp"):
                        lval = self.locs.get(keys=(eid, scheme))
                        if lval:
                            exists = True
                            copy.locs.put(keys=(eid, scheme), val=lval)
                    if exists:
                        copy.ends.put(keys=(cid, role, eid), val=val)

                for name in self.SubDbNames:
                    src_store = copy._stores.get(name)
                    dst_store = self._stores.get(name)
                    if src_store is not None and dst_store is not None:
                        dst_store.items.clear()
                        dst_store.items.update(src_store.items)
                        dst_store.dirty = True
                self.reload()
                await self.flush()
            finally:
                await copy.aclose(clear=True)


class WebBaserDoer(doing.Doer):
    """Doer for WebBaser lifecycle management within the hio scheduler.

    Manages the close-on-exit side of the WebBaser lifecycle.  Because hio's
    Doer.enter() and Doer.exit() are synchronous, and WebBaser.reopen()
    is async, the baser must already be opened before the Doist starts.

    On exit, calls the synchronous :meth:`WebBaser.close` which schedules a
    tracked flush to IndexedDB. For guaranteed flush semantics, call
    ``await baser.aclose()`` from an async context before the Doer exits (e.g.
    in an ``AsyncRecurDoer.recur_async()`` finally block).

    Typical usage::

        baser = WebBaser(name="wallet", temp=False)
        await baser.reopen(storageOpener=backend.open)
        doer = WebBaserDoer(baser=baser)
        doist.doers = [doer, ...]
        try:
            await doist.ado()
        finally:
            await baser.aclose()
    """

    def __init__(self, baser, **kwa):
        super().__init__(**kwa)
        self.baser = baser

    def enter(self, *, temp=None):
        if not self.baser.opened:
            raise RuntimeError(
                "WebBaser must be opened before WebBaserDoer.enter()")

    def exit(self):
        if self.baser.opened:
            self.baser.close(clear=self.baser.temp)
