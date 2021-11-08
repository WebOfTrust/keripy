# -*- encoding: utf-8 -*-
"""
KERI
keri.app.habbing module

"""
import json
from contextlib import contextmanager
from urllib.parse import urlsplit

from hio.base import doing
from hio.help import hicting


from .. import help
from .. import kering
from ..kering import ValidationError, MissingDelegationError, MissingSignatureError
from ..core import coring, eventing, parsing
from ..core.coring import Serder
from ..db import dbing, basing
from ..db.dbing import snKey, dgKey
from . import keeping, configing

logger = help.ogler.getLogger()


@contextmanager
def openHab(name="test", base="", salt=b'0123456789abcdef', temp=True, **kwa):
    """
    Context manager wrapper for Habitat instance.
    Defaults to temporary database and keeper.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        name(str): name of habitat to create
        salt(bytes): passed to habitat to use for inception
        temp(bool): indicates if this uses temporary databases

    """

    with basing.openDB(name=base if base else name, temp=temp) as db, \
            keeping.openKS(name=base if base else name, temp=temp) as ks, \
            configing.openCF(name=name, base=base, temp=temp) as cf:
        salt = coring.Salter(raw=salt).qb64
        hab = Habitat(name=name, base=base, ks=ks, db=db, cf=cf, temp=temp,
                      salt=salt, icount=1, isith=1, ncount=1, nsith=1, **kwa)

        yield hab


@contextmanager
def existingHab(name="test", **kwa):
    """
    Context manager wrapper for existing Habitat instance.
    Will raise exception if Habitat and database has not already been created.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        name(str): name of habitat to create
    """

    with basing.openDB(name=name, temp=False, reload=True) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        hab = Habitat(name=name, ks=ks, db=db, temp=False, create=False, **kwa)
        yield hab


class Habitat:
    """
    Habitat class provides direct mode controller's local shared habitat
       e.g. context or environment

    Attributes:
        name (str): alias of controller
        transferable (bool): True means pre is transferable (default)
                    False means pre is nontransferable
        temp (bool): True for testing it modifies tier of salty key
            generation algorithm and persistence of db and ks
        erase (bool): If True erase old private keys, Otherwise not.
        db (basing.Baser): lmdb data base for KEL etc
        ks (keeping.Keeper): lmdb key store
        cf (configing.Configer): config file instance
        ridx (int): rotation index (inception == 0) needed for key replay
        kvy (eventing.Kevery): instance for local processing of local msgs
        psr (parsing.Parser):  parses local messages for .kvy
        mgr (keeping.Manager): creates and rotates keys in key store
        pre (str): qb64 prefix of own local controller
        inited (bool): True means fully initialized wrt databases.
                          False means not yet fully initialized


    Properties:
        kever (Kever): instance of key state of local controller
        kevers (dict): of eventing.Kever(s) keyed by qb64 prefix
        iserder (coring.Serder): own inception event
        prefixes (OrderedSet): local prefixes for .db

    """

    def __init__(self, *, name='test', base="", ks=None, db=None, cf=None,
                 transferable=True, temp=False, erase=True, create=True,
                 **kwa):
        """
        Initialize instance.

        Parameters:
            name (str): alias name for local controller of habitat
            base (str): optional directory path segment inserted before name
                that allows further differentation with a hierarchy. "" means
                optional.
            ks (Keeper):  keystore lmdb subclass instance
            db (Baser): database lmdb subclass instance
            cf (Configer): config file instance
            transferable (bool): True means pre is transferable (default)
                    False means pre is nontransferable
            temp (bool): True means store .ks, .db, and .cf in /tmp for testing
            erase (bool): True means erase private keys once stale
            create (bool): True means create if identifier doesn't already exist

        Parameters: Passed through via kwa to setup for later init
            seed (str): qb64 private-signing key (seed) for the aeid from which
                the private decryption key may be derived. If aeid stored in
                database is not empty then seed may required to do any key
                management operations. The seed value is memory only and MUST NOT
                be persisted to the database for the manager with which it is used.
                It MUST only be loaded once when the process that runs the Manager
                is initialized. Its presence acts as an authentication, authorization,
                and decryption secret for the Manager and must be stored on
                another device from the device that runs the Manager.
            aeid (str): qb64 of non-transferable identifier prefix for
                authentication and encryption of secrets in keeper. If provided
                aeid (not None) and different from aeid stored in database then
                all secrets are re-encrypted using new aeid. In this case the
                provided prikey must not be empty. A change in aeid should require
                a second authentication mechanism besides the prikey.
            secrecies (list): of list of secrets to preload key pairs if any
            code (str): prefix derivation code
            isith (Union[int, str, list]): incepting signing threshold as int, str hex, or list
            icount (int): incepting key count for number of keys
            nsith (Union[int, str, list]): next signing threshold as int, str hex or list
            ncount (int): next key count for number of next keys
            toad (Union[int,str]): int or str hex of witness threshold
            wits (list): of qb64 prefixes of witnesses
            salt (str): qb64 salt for creating key pairs
            tier (str): security tier for generating keys from salt

        """
        self.name = name
        self.transferable = transferable
        self.temp = temp
        self.erase = erase
        self.create = create
        self.db = db if db is not None else basing.Baser(name=base if base else name,
                                                         temp=self.temp,
                                                         reopen=True)
        self.ks = ks if ks is not None else keeping.Keeper(name=base if base else name,
                                                           temp=self.temp,
                                                           reopen=True)
        self.cf = cf if cf is not None else configing.Configer(name=name,
                                                               base=base,
                                                               temp=self.temp,
                                                               reopen=True)
        self.ridx = 0  # rotation index of latest establishment event
        self.kvy = eventing.Kevery(db=self.db, lax=False, local=True)
        self.psr = parsing.Parser(framed=True, kvy=self.kvy)
        self.mgr = None  # wait to setup until after ks is known to be opened
        self.pre = None  # wait to setup until after db is known to be opened
        self.delpre = None
        self.inited = False
        self.accepted = False
        self.delpre = None
        self.delserder = None
        self.delverfers = None
        self.delsigers = None

        # save init kwy word arg parameters as ._inits in order to later finish
        # init setup elseqhere after databases are opened if not below
        self._inits = kwa

        if self.db.opened and self.ks.opened:
            self.setup(**self._inits)  # finish setup later

    def setup(self, *, seed=None, aeid=None, secrecies=None, code=coring.MtrDex.Blake3_256,
              isith=None, icount=1, nsith=None, ncount=None,
              toad=None, wits=None, algo=None, salt=None, tier=None, delpre=None, estOnly=False):
        """
        Setup habitat. Assumes that both .db and .ks have been opened.
        This allows dependency injection of .db and .ks into habitat instance
        prior to .db and .kx being opened to accomodate asynchronous process
        setup of these resources. Putting the .db and .ks associated
        initialization here enables asynchronous opening .db and .ks after
        Baser and Keeper instances are instantiated. First call to .setup will
        initialize databases (vacuous initialization).

        Parameters:
            seed (str): qb64 private-signing key (seed) for the aeid from which
                the private decryption key may be derived. If aeid stored in
                database is not empty then seed may required to do any key
                management operations. The seed value is memory only and MUST NOT
                be persisted to the database for the manager with which it is used.
                It MUST only be loaded once when the process that runs the Manager
                is initialized. Its presence acts as an authentication, authorization,
                and decryption secret for the Manager and must be stored on
                another device from the device that runs the Manager.
            aeid (str): qb64 of non-transferable identifier prefix for
                authentication and encryption of secrets in keeper. If provided
                aeid (not None) and different from aeid stored in database then
                all secrets are re-encrypted using new aeid. In this case the
                provided prikey must not be empty. A change in aeid should require
                a second authentication mechanism besides the prikey.
            secrecies is list of list of secrets to preload key pairs if any
            code is prefix derivation code
            isith is incepting signing threshold as int, str hex, or list
            icount is incepting key count for number of keys
            nsith is next signing threshold as int, str hex or list
            ncount is next key count for number of next keys
            toad is int or str hex of witness threshold
            wits is list of qb64 prefixes of witnesses
            salt is str for algorithm (randy or salty) for creating key pairs
                default is root algo which defaults to salty
            salt is qb64 salt for creating key pairs
            tier is security tier for generating keys from salt
        """
        if not (self.ks.opened and self.db.opened):
            raise kering.ClosedError("Attempt to setup Habitat with closed "
                                     "database, .ks or .db.")
        if nsith is None:
            nsith = isith
        if ncount is None:
            ncount = icount
        if not self.transferable:
            ncount = 0  # next count
            code = coring.MtrDex.Ed25519N
        pidx = None
        if delpre is not None:
            self.delpre = delpre

        # for persisted Habitats, check the KOM first to see if there is an existing
        # one we can restart from otherwise initialize a new one
        existing = False
        if not self.temp:
            ex = self.db.habs.get(keys=self.name)
            if ex is not None:  # replace params with persisted values from db

                # have to check if we are a group identifier and if so, we need to load the
                # keys from our local identifier that's in the group, not the group itself.
                gid = self.db.gids.get(keys=ex.prefix)
                if gid is not None:
                    prefix = gid.lid
                else:
                    prefix = ex.prefix

                # found existing habitat, otherwise leave __init__ to incept a new one.
                prms = self.ks.prms.get(prefix)
                algo = prms.algo
                salt = prms.salt
                tier = prms.tier
                pidx = prms.pidx
                self.pre = ex.prefix
                existing = True

        if not existing and not self.create:
            raise kering.ConfigurationError("Improper Habitat creating for create")

        if salt is None:
            salt = coring.Salter(raw=b'0123456789abcdef').qb64

        self.mgr = keeping.Manager(ks=self.ks, seed=seed, aeid=aeid, pidx=pidx,
                                   algo=algo, salt=salt, tier=tier)

        if existing:
            self.reinitialize()
        else:
            if secrecies:
                verferies, digers = self.mgr.ingest(secrecies,
                                                    ncount=ncount,
                                                    stem=self.name,
                                                    transferable=self.transferable,
                                                    temp=self.temp)
                opre = verferies[0][0].qb64  # old pre default needed for .replay
                verfers, digers, cst, nst = self.mgr.replay(pre=opre, ridx=self.ridx)
            else:
                verfers, digers, cst, nst = self.mgr.incept(icount=icount,
                                                            isith=isith,
                                                            ncount=ncount,
                                                            nsith=nsith,
                                                            stem=self.name,
                                                            transferable=self.transferable,
                                                            temp=self.temp)

            opre = verfers[0].qb64  # old pre default move below to new pre from incept
            if digers:
                nxt = coring.Nexter(sith=nst,
                                    digs=[diger.qb64 for diger in digers]).qb64
            else:
                nxt = ""

            cnfg = []
            if estOnly:
                cnfg.append(eventing.TraitCodex.EstOnly)

            if self.delpre:
                serder = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                          delpre=self.delpre,
                                          wits=wits,
                                          toad=toad,
                                          cnfg=cnfg,
                                          nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)
                # save off serder and verfers for delegation acceptance
                self.delserder = serder
                self.delverfers = verfers
            else:
                serder = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                         sith=cst,
                                         nxt=nxt,
                                         toad=toad,
                                         wits=wits,
                                         cnfg=cnfg,
                                         code=code)

            self.pre = serder.ked["i"]  # new pre
            self.mgr.move(old=opre, new=self.pre)

            # may want db method that updates .habs. and .prefixes together
            self.db.habs.put(keys=self.name,
                             val=basing.HabitatRecord(prefix=self.pre))
            self.prefixes.add(self.pre)

            # create inception event
            sigers = self.mgr.sign(ser=serder.raw, verfers=verfers)
            if self.delpre:
                self.delsigers = sigers
            # during delegation initialization of a habitat we ignore the MissingDelegationError and
            # MissingSignatureError
            try:
                self.kvy.processEvent(serder=serder, sigers=sigers)
            except MissingDelegationError or MissingSignatureError:
                pass
            except Exception as ex:
                raise kering.ConfigurationError("Improper Habitat inception for "
                                                "pre={} {}".format(self.pre, ex))

            self.accepted = self.pre in self.kevers

            # read in self.cf config file and process any oobis or endpoints
            self.reconfigure()

        self.inited = True

    def delegationAccepted(self):
        # process escrow
        self.kvy.processEscrows()
        if self.pre not in self.kevers:
            raise Exception()

        self.accepted = True

    def delegatedRotationAccepted(self):
        # process escrow
        self.kvy.processEscrows()
        if self.pre not in self.kevers:
            raise Exception()

        self.ridx += 1

    def reinitialize(self):
        if self.pre is None:
            raise kering.ConfigurationError("Improper Habitat reinitialization missing prefix")

        # if it's delegated, and not accepted, and not in kevers, no error
        # if it's delegated and accepted and not in kevers, error
        # if it's not delegated and not in kevers, error
        if (self.delpre and self.accepted) and self.pre not in self.kevers \
                or not self.delpre and self.pre not in self.kevers:
            raise kering.ConfigurationError("Missing Habitat KEL for "
                                            "pre={}.".format(self.pre))

        self.prefixes.add(self.pre)  # ordered set so add is idempotent

        # ridx for replay may be an issue when loading from existing
        self.ridx = self.ks.sits.get(self.pre).new.ridx


    def reconfigure(self):
        """
        Apply configuration from config file managed by .cf.  Assumes that .pre
        and signing keys have been setup in order to create own endpoint auth when
        provided in .cf.

        conf
        {
          dt: "isodatetime",
          curls: ["tcp://localhost:5620/"],
          iurls: ["tcp://localhost:5621/?name=eve"],
        }
        """

        conf = self.cf.get()
        if "dt" in conf: # datetime of config file
            dt = help.fromIso8601(conf["dt"])  # raises error if not convert
            msgs = bytearray()
            msgs.extend(self.makeEndRole(eid=self.pre,
                                       role=kering.Roles.controller,
                                       stamp=help.toIso8601(dt=dt)))
            if "curls" in conf:
                curls = conf["curls"]
                for url in curls:
                    splits = urlsplit(url)
                    scheme = (splits.scheme if splits.scheme in kering.Schemes
                                            else kering.Schemes.http)
                    msgs.extend(self.makeLocScheme(url=url,
                                                 scheme=scheme,
                                                 stamp=help.toIso8601(dt=dt)))
            self.psr.parse(ims=msgs)

            if "iurls" in conf:  # process OOBI URLs
                for url in conf["iurls"]:
                    splits = urlsplit(url)


    def recreate(self, serder, opre, verfers):

        self.pre = serder.ked["i"]  # new pre
        self.mgr.move(old=opre, new=self.pre)

        habr = self.db.habs.get(self.name)
        # may want db method that updates .habs. and .prefixes together
        self.db.habs.pin(keys=self.name,
                         val=basing.HabitatRecord(prefix=self.pre, watchers=habr.watchers))
        self.prefixes.add(self.pre)

        # self.kvy = eventing.Kevery(db=self.db, lax=False, local=True)
        # create inception event
        sigers = self.mgr.sign(ser=serder.raw, verfers=verfers)
        self.kvy.processEvent(serder=serder, sigers=sigers)
        # self.psr = parsing.Parser(framed=True, kvy=self.kvy)
        if self.pre not in self.kevers:
            raise kering.ConfigurationError("Improper Habitat inception for "
                                            "pre={}.".format(self.pre))

    @property
    def iserder(self):
        """
        Return serder of inception event
        """
        if (dig := self.db.getKeLast(eventing.snKey(pre=self.pre, sn=0))) is None:
            raise kering.ConfigurationError("Missing inception event in KEL for "
                                            "Habitat pre={}.".format(self.pre))
        if (raw := self.db.getEvt(eventing.dgKey(pre=self.pre, dig=bytes(dig)))) is None:
            raise kering.ConfigurationError("Missing inception event for "
                                            "Habitat pre={}.".format(self.pre))
        return coring.Serder(raw=bytes(raw))

    @property
    def kevers(self):
        """
        Returns .db.kevers
        """
        return self.db.kevers

    @property
    def kever(self):
        """
        Returns kever for its .pre
        """
        return self.kevers[self.pre]

    @property
    def prefixes(self):
        """
        Returns .db.prefixes
        """
        return self.db.prefixes

    def group(self):
        return self.db.gids.get(self.pre)

    def rotate(self, sith=None, count=None, erase=None,
               toad=None, cuts=None, adds=None, data=None):
        """
        Perform rotation operation. Register rotation in database.
        Returns: bytearrayrotation message with attached signatures.

        Parameters:
            sith is next signing threshold as int or str hex or list of str weights
            count is int next number of signing keys
            erase is Boolean True means erase stale keys
            toad is int or str hex of witness threshold after cuts and adds
            cuts is list of qb64 pre of witnesses to be removed from witness list
            adds is list of qb64 pre of witnesses to be added to witness list
            data is list of dicts of committed data such as seals

        """
        if erase is not None:
            self.erase = erase

        kever = self.kever  # kever.pre == self.pre
        if sith is None:
            sith = kever.tholder.sith  # use previous sith
        if count is None:
            count = len(kever.verfers)  # use previous count

        try:
            verfers, digers, cst, nst = self.mgr.replay(pre=self.pre,
                                                        ridx=self.ridx + 1,
                                                        erase=erase)
        except IndexError:
            verfers, digers, cst, nst = self.mgr.rotate(pre=self.pre,
                                                        count=count,  # old next is new current
                                                        sith=sith,
                                                        temp=self.temp,
                                                        erase=erase)

        if digers:
            nxt = coring.Nexter(sith=nst,
                                digs=[diger.qb64 for diger in digers]).qb64
        else:
            nxt = ""

        # this is wrong sith is not kever.tholder.sith as next was different
        if kever.delegator is not None:
            serder = eventing.deltate(pre=kever.prefixer.qb64,
                                      keys=[verfer.qb64 for verfer in verfers],
                                      dig=kever.serder.diger.qb64,
                                      sn=kever.sn + 1,
                                      sith=cst,
                                      nxt=nxt,
                                      toad=toad,
                                      wits=kever.wits,
                                      cuts=cuts,
                                      adds=adds,
                                      data=data)
        else:
            serder = eventing.rotate(pre=kever.prefixer.qb64,
                                     keys=[verfer.qb64 for verfer in verfers],
                                     dig=kever.serder.diger.qb64,
                                     sn=kever.sn + 1,
                                     sith=cst,
                                     nxt=nxt,
                                     toad=toad,
                                     wits=kever.wits,
                                     cuts=cuts,
                                     adds=adds,
                                     data=data)

        sigers = self.mgr.sign(ser=serder.raw, verfers=verfers)
        # update own key event verifier state
        msg = eventing.messagize(serder, sigers=sigers)

        try:
            self.kvy.processEvent(serder=serder, sigers=sigers)
        except MissingDelegationError or MissingSignatureError:
            pass
        except Exception as ex:
            raise kering.ValidationError("Improper Habitat rotation for "
                                         "pre={}.".format(self.pre))
        else:
            self.ridx += 1  # successful rotate so increment for next time

        return msg


    def interact(self, data=None):
        """
        Perform interaction operation. Register interaction in database.
        Returns: bytearray interaction message with attached signatures.
        """
        kever = self.kever
        serder = eventing.interact(pre=kever.prefixer.qb64,
                                   dig=kever.serder.diger.qb64,
                                   sn=kever.sn + 1,
                                   data=data)

        sigers = self.mgr.sign(ser=serder.raw, verfers=kever.verfers)
        # update own key event verifier state
        # self.kvy.processEvent(serder=serder, sigers=sigers)
        seal = data if isinstance(data, eventing.SealEvent) else None
        msg = eventing.messagize(serder, sigers=sigers, seal=seal)
        self.psr.parseOne(ims=bytearray(msg))  # make copy as kvy deletes
        if kever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Habitat interaction for "
                                         "pre={}.".format(self.pre))

        return msg


    def query(self, pre, query=None, **kwa):
        """
        Returns query message for querying at route for query parameter 'i' = pre

        Need to fix this
        Assumes query is always for querying route = 'logs' to replay logs
        need to remove pre parameter and have caller insert in query

        """

        query = query if query is not None else dict()
        query['i'] = pre
        serder = eventing.query(query=query, **kwa)

        return self.endorse(serder, last=True)


    def receipt(self, serder):
        """
        Returns own receipt, rct, message of serder with count code and receipt
        couples (pre+cig)
        Builds msg and then processes it into own db to validate
        """
        ked = serder.ked
        reserder = eventing.receipt(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    dig=serder.dig)

        # sign serder event
        if self.kever.prefixer.transferable:
            seal = eventing.SealEvent(i=self.pre,
                                      s="{:x}".format(self.kever.lastEst.s),
                                      d=self.kever.lastEst.d)
            sigers = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=True)
            msg = eventing.messagize(serder=reserder, sigers=sigers, seal=seal)
        else:
            cigars = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=False)
            msg = eventing.messagize(reserder, cigars=cigars)

        self.psr.parseOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def witness(self, serder):
        """
        Returns own receipt, rct, message of serder with count code and witness
        indexed receipt signatures if key state of serder.pre shows that own pre
        is a current witness of event in serder
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
            raise ValueError("Attempt by {} to witness event of {} when not a "
                             "witness in wits={}.".format(self.pre,
                                                          serder.pre,
                                                          kever.wits))
        index = kever.wits.index(self.pre)

        reserder = eventing.receipt(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    dig=serder.dig)
        # sign serder event
        wigers = self.mgr.sign(ser=serder.raw,
                               pubs=[self.pre],
                               indices=[index])

        msg = eventing.messagize(reserder, wigers=wigers, pipelined=True)
        self.psr.parseOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def endorse(self, serder, last=False, pipelined=True):
        """
        Returns msg with own endorsement of msg from serder with attached signature
        groups based on own pre transferable or non-transferable.

        Parameters:
            serder (Serder): instance of msg
            last (bool): True means use SealLast. False means use SealEvent
                         query messages use SealLast
            pipelined (bool): True means use pipelining attachment code

        Useful for endorsing message when provided via serder such as state,
        reply, query or similar.
        """
        if self.kever.prefixer.transferable:
            # create SealEvent or SealLast for endorser's est evt whose keys are
            # used to sign
            group = self.db.gids.get(self.pre)  # is it a group ID
            if group is None:  # not a group use own kever
                kever = self.kever
                indices = None  # use default order
            else:  # group so use gid kever
                kever = self.kevers[group.gid]
                indices = [group.aids.index(group.lid)]  # use group order

            if last:
                seal = eventing.SealLast(i=kever.prefixer.qb64)
            else:
                seal = eventing.SealEvent(i=kever.prefixer.qb64,
                                          s=hex(kever.lastEst.s),
                                          d=kever.lastEst.d)

            sigers = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=True,
                                   indices=indices)

            msg = eventing.messagize(serder=serder,
                                     sigers=sigers,
                                     seal=seal,
                                     pipelined=pipelined)

        else:
            cigars = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=False)
            msg = eventing.messagize(serder=serder,
                                     cigars=cigars,
                                     pipelined=pipelined)

        return msg


    def verifiage(self, pre=None, sn=0, dig=None):
        """
        Returns the Tholder and Verfers for the provided identifier prefix.
        Default pre is own .pre

        Parameters:
            pre(str) is qb64 str of bytes of identifier prefix.
                      default is own .pre
            sn(int) is the sequence number of the est event
            dig(str) is qb64 str of digest of est event

        """
        if not pre:
            pre = self.pre

        prefixer = coring.Prefixer(qb64=pre)
        if prefixer.transferable:
            # receipted event and receipter in database so get receipter est evt
            # retrieve dig of last event at sn of est evt of receipter.
            sdig = self.db.getKeLast(key=snKey(pre=prefixer.qb64b,
                                               sn=sn))
            if sdig is None:
                # receipter's est event not yet in receipters's KEL
                raise ValidationError("key event sn {} for pre {} is not yet in KEL"
                                      "".format(sn, pre))
            # retrieve last event itself of receipter est evt from sdig
            sraw = self.db.getEvt(key=dgKey(pre=prefixer.qb64b, dig=bytes(sdig)))
            # assumes db ensures that sraw must not be none because sdig was in KE
            sserder = Serder(raw=bytes(sraw))
            if dig is not None and not sserder.compare(diger=coring.Diger(qb64=dig)):  # endorser's dig not match event
                raise ValidationError("Bad proof sig group at sn = {}"
                                      " for ksn = {}."
                                      "".format(sn, sserder.ked))

            verfers = sserder.verfers
            tholder = sserder.tholder

        else:
            verfers = [coring.Verfer(qb64=pre)]
            tholder = coring.Tholder(sith="1")

        return tholder, verfers


    def replay(self, pre=None, fn=0):
        """
        Returns replay of FEL first seen event log for pre starting from fn
        Default pre is own .pre

        Parameters:
            pre is qb64 str or bytes of identifier prefix.
                default is own .pre
            fn is int first seen ordering number

        """
        if not pre:
            pre = self.pre
        msgs = bytearray()
        for msg in self.db.clonePreIter(pre=pre, fn=fn):
            msgs.extend(msg)
        return msgs


    def replayAll(self, key=b''):
        """
        Returns replay of FEL first seen event log for all pre starting at key

        Parameters:
            key (bytes): fnKey(pre, fn)

        """
        msgs = bytearray()
        for msg in self.db.cloneAllPreIter(key=key):
            msgs.extend(msg)
        return msgs

    def makeOtherEvent(self, pre, sn):
        """
        Returns: messagized bytearray message with attached signatures of
                 own event at sequence number sn from retrieving event at sn
                 and associated signatures from database.

        Parameters:
            sn is int sequence number of event
        """
        if pre not in self.kevers:
            return None

        msg = bytearray()
        dig = self.db.getKeLast(dbing.snKey(pre, sn))
        if dig is None:
            raise kering.MissingEntryError("Missing event for pre={} at sn={}."
                                           "".format(pre, sn))
        dig = bytes(dig)
        key = dbing.dgKey(pre, dig)  # digest key
        msg.extend(self.db.getEvt(key))
        msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=self.db.cntSigs(key)).qb64b)  # attach cnt
        for sig in self.db.getSigsIter(key):
            msg.extend(sig)  # attach sig
        return (msg)

    def fetchEnd(self, cid: str, role: str, eid: str):
        """
        Returns:
            endpoint (basing.EndpointRecord): instance or None
        """
        return self.db.ends.get(keys=(cid, role, eid))

    def fetchLoc(self, eid: str, scheme: str = kering.Schemes.http):
        """
        Returns:
            location (basing.LocationRecord): instance or None
        """
        return self.db.locs.get(keys=(eid, scheme))

    def fetchEndAllowed(self, cid: str, role: str, eid: str):
        """
        Returns:
            allowed (bool): True if eid is allowed as endpoint provider for cid
                          in role. False otherwise.
        Parameters:
            cid (str): identifier prefix qb64 of controller authZ endpoint provided
                       eid in role
            role (str): endpoint role such as (controller, witness, watcher, etc)
            eid (str): identifier prefix qb64 of endpoint provider in role
        """
        end = self.db.ends.get(keys=(cid, role, eid))
        return (end.allowed if end else None)

    def fetchEndEnabled(self, cid: str, role: str, eid: str):
        """
        Returns:
            allowed (bool): True if eid is allowed as endpoint provider for cid
                          in role. False otherwise.
        Parameters:
            cid (str): identifier prefix qb64 of controller authZ endpoint provided
                       eid in role
            role (str): endpoint role such as (controller, witness, watcher, etc)
            eid (str): identifier prefix qb64 of endpoint provider in role
        """
        end = self.db.ends.get(keys=(cid, role, eid))
        return (end.enabled if end else None)

    def fetchEndAuthzed(self, cid: str, role: str, eid: str):
        """
        Returns:
            allowed (bool): True if eid is allowed as endpoint provider for cid
                          in role. False otherwise.
        Parameters:
            cid (str): identifier prefix qb64 of controller authZ endpoint provided
                       eid in role
            role (str): endpoint role such as (controller, witness, watcher, etc)
            eid (str): identifier prefix qb64 of endpoint provider in role
        """
        end = self.db.ends.get(keys=(cid, role, eid))
        return ((end.enabled or end.allowed) if end else None)

    def fetchUrl(self, eid: str, scheme: str = kering.Schemes.http):
        """
        Returns:
            url (str): for endpoint provider given by eid
                       empty string when url is nullified
                       None when no location record
        """
        loc = self.db.locs.get(keys=(eid, scheme))
        return (loc.url if loc else loc)

    def fetchUrls(self, eid: str, scheme: str = ""):
        """
        Returns:
           surls (hicting.Mict): urls keyed by scheme for given eid. Assumes that
                user independently verifies that the eid is allowed for a
                given cid and role. If url is empty then does not return

        Parameters:
            eid (str): identifier prefix qb64 of endpoint provider
            scheme (str): url scheme
        """
        return hicting.Mict([(keys[1], loc.url) for keys, loc in
                             self.db.locs.getItemIter(keys=(eid, scheme)) if loc.url])

    def fetchRoleUrls(self, cid: str, *, role: str = "", scheme: str = "",
                      eids=None, enabled: bool = True, allowed: bool = True):
        """
        Returns:
           rurls (hicting.Mict):  of nested dicts. The top level dict rurls is keyed by
                        role for a given cid. Each value in rurls is eurls dict
                        keyed by the eid of authorized endpoint provider and
                        each value in eurls is a surls dict keyed by scheme

        Parameters:
            cid (str): identifier prefix qb64 of controller authZ endpoint provided
                       eid in role
            role (str): endpoint role such as (controller, witness, watcher, etc)
            scheme (str): url scheme
            eids (list): when provided restrict returns to only eids in eids
            enabled (bool): True means fetch any allowed witnesses as well
            allowed (bool): True means fetech any enabled witnesses as well
        """
        if eids is None:
            eids = []

        rurls = hicting.Mict()

        if role == kering.Roles.witness:
            if (kever := self.kevers[cid] if cid in self.kevers else None):
                # latest key state for cid
                for eid in kever.wits:
                    if not eids or eid in eids:
                        surls = self.fetchUrls(eid, scheme=scheme)
                        if surls:
                            rurls.add(kering.Roles.witness,
                                      hicting.Mict([(eid, surls)]))

        for (_, erole, eid), end in self.db.ends.getItemIter(keys=(cid, role)):
            if (enabled and end.enabled) or (allowed and end.allowed):
                if not eids or eid in eids:
                    surls = self.fetchUrls(eid, scheme=scheme)
                    if surls:
                        rurls.add(erole, hicting.Mict([(eid, surls)]))
        return rurls

    def fetchWitnessUrls(self, cid: str, scheme: str = "", eids=None,
                         enabled: bool = True, allowed: bool = True):
        """
        Fetch witness urls for witnesses of cid at latest key state or enabled or
        allowed witnesses if not a witness at latest key state.

        Returns:
           rurls (hicting.Mict):  of nested dicts. The top level dict rurls is keyed by
                        role for a given cid. Each value in rurls is eurls dict
                        dict keyed by the eid of authorized endpoint provider and
                        each value in eurls is a surls dict keyed by scheme

        Parameters:
            cid (str): identifier prefix qb64 of controller authZ endpoint provided
                       eid is witness
            scheme (str): url scheme
            eids (list): when provided restrict returns to only eids in eids
            enabled (bool): True means fetch any allowed witnesses as well
            allowed (bool): True means fetech any enabled witnesses as well
        """
        return (self.fetchRoleUrls(cid=cid,
                                   role=kering.Roles.witness,
                                   scheme=scheme,
                                   eids=eids,
                                   enabled=enabled,
                                   allowed=allowed))

    def reply(self, **kwa):
        """
        Returns:
            msg (bytearray): reply message

        Parameters:
            route is route path string that indicates data flow handler (behavior)
                to processs the reply
            data is list of dicts of comitted data such as seals
            dts is date-time-stamp of message at time or creation
            version is Version instance
            kind is serialization kind
        """
        return self.endorse(eventing.reply(**kwa))


    def makeEndRole(self, eid, role=kering.Roles.controller, allow=True, stamp=None):
        """
        Returns:
            msg (bytearray): reply message allowing/disallowing endpoint provider
               eid in role

        Parameters:
            eid (str): qb64 of endpoint provider to be authorized
            role (str): authorized role for eid
            allow (bool): True means add eid at role as authorized
                          False means cut eid at role as unauthorized
            stamp (str): date-time-stamp RFC-3339 profile of iso8601 datetime.
                          None means use now.
        """
        data = dict(cid=self.pre, role=role, eid=eid)
        route = "/end/role/add" if allow else "/end/role/cut"
        return self.reply(route=route, data=data, stamp=stamp)

    def makeLocScheme(self, url, scheme="http", stamp=None):
        """
        Returns:
           msg (bytearray): reply message of own url service endpoint at scheme

        Parameters:
            url (str): url of endpoint, may have scheme missing or not
                       If url is empty then nullifies location
            scheme (str): url scheme must matche scheme in url if any
            stamp (str): date-time-stamp RFC-3339 profile of iso8601 datetime.
                          None means use now.

        """
        data = data = dict(eid=self.pre, scheme=scheme, url=url)
        return self.reply(route="/loc/scheme", data=data, stamp=stamp)

    def replyLocScheme(self, eid, scheme=None):
        """
        Returns a reply message stream composed of entries authed by the given
        eid from the appropriate reply database including associated attachments
        in order to disseminate (percolate) BADA reply data authentication proofs.

        Currently uses promiscuous model for permitting endpoint discovery.
        Future is to use identity constraint graph to constrain discovery
        of whom by whom.

        eid and and not scheme then:
            loc url for all schemes at eid

        eid and scheme then:
            loc url for scheme at eid

        Parameters:
            eid (str): endpoint provider id
            scheme (str): url scheme
        """

    def replyEndRole(self, cid, role=None, eids=None, scheme=None):
        """
        Returns a reply message stream composed of entries authed by the given
        cid from the appropriate reply database including associated attachments
        in order to disseminate (percolate) BADA reply data authentication proofs.

        Currently uses promiscuous model for permitting endpoint discovery.
        Future is to use identity constraint graph to constrain discovery
        of whom by whom.

        cid and not role and not scheme then:
            end authz for all eids in all roles and loc url for all schemes at each eid
            if eids then only eids in eids else all eids

        cid and not role and scheme then:
            end authz for all eid in all roles and loc url for scheme at each eid
            if eids then only eids in eids else all eids

        cid and role and not scheme then:
            end authz for all eid in role and loc url for all schemes at each eid
            if eids then only eids in eids else all eids

        cid and role and scheme then:
            end authz for all eid in role and loc url for scheme at each eid
            if eids then only eids in eids else all eids


        Parameters:
            cid (str): identifier prefix qb64 of controller authZ endpoint provided
                       eid is witness
            role (str): authorized role for eid
            eids (list): when provided restrict returns to only eids in eids
            scheme (str): url scheme
        """
        if eids is None:
            eids = []

    def replyToOobi(self, aid):
        """
        Returns a reply message stream composed of entries authed by the given
        aid from the appropriate reply database including associated attachments
        in order to disseminate (percolate) BADA reply data authentication proofs.

        Currently uses promiscuous model for permitting oobi initiated endpoint
        discovery. Future is to use identity constraint graph to constrain
        discovery of whom by whom.

        Parameters:
            aid (str): qb64 of identifier in oobi, may be cid or eid

        """
        # default logic is that if self.pre is witness of aid and has a loc url
        # for self then reply with loc scheme for all witnesses even if self
        # not permiteed in .habs.oobis

    def makeOwnEvent(self, sn):
        """
        Returns: messagized bytearray message with attached signatures of
                 own event at sequence number sn from retrieving event at sn
                 and associated signatures from database.

        Parameters:
            sn is int sequence number of event
        """
        msg = bytearray()
        dig = self.db.getKeLast(dbing.snKey(self.pre, sn))
        if dig is None:
            raise kering.MissingEntryError("Missing event for pre={} at sn={}."
                                           "".format(self.pre, sn))
        dig = bytes(dig)
        key = dbing.dgKey(self.pre, dig)  # digest key
        msg.extend(self.db.getEvt(key))
        msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=self.db.cntSigs(key)).qb64b)  # attach cnt
        for sig in self.db.getSigsIter(key):
            msg.extend(sig)  # attach sig
        return (msg)


    def makeOwnInception(self):
        """
        Returns: messagized bytearray message with attached signatures of
                 own inception event by retrieving event and signatures
                 from database.
        """
        return self.makeOwnEvent(sn=0)


    def processCues(self, cues):
        """
        Returns bytearray of messages as a result of processing all cues

        Parameters:
           cues is deque of cues
        """
        msgs = bytearray()  # outgoing messages
        for msg in self.processCuesIter(cues):
            msgs.extend(msg)
        return msgs


    def processCuesIter(self, cues):
        """
        Iterate through cues and yields one or more msgs for each cue.

        Parameters:
            cues is deque of cues

        """
        while cues:  # iteratively process each cue in cues
            msgs = bytearray()
            cue = cues.popleft()
            cueKin = cue["kin"]  # type or kind of cue

            if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                cuedSerder = cue["serder"]  # Serder of received event for other pre
                cuedKed = cuedSerder.ked
                cuedPrefixer = coring.Prefixer(qb64=cuedKed["i"])
                logger.info("%s got cue: kin=%s\n%s\n\n", self.pre, cueKin,
                            json.dumps(cuedKed, indent=1))

                if cuedKed["t"] == coring.Ilks.icp:
                    dgkey = dbing.dgKey(self.pre, self.iserder.dig)
                    found = False
                    if cuedPrefixer.transferable:  # find if have rct from other pre for own icp
                        for quadruple in self.db.getVrcsIter(dgkey):
                            if bytes(quadruple).decode("utf-8").startswith(cuedKed["i"]):
                                found = True  # yes so don't send own inception
                    else:  # find if already rcts of own icp
                        for couple in self.db.getRctsIter(dgkey):
                            if bytes(couple).decode("utf-8").startswith(cuedKed["i"]):
                                found = True  # yes so don't send own inception

                    if not found:  # no receipt from remote so send own inception
                        # no vrcs or rct of own icp from remote so send own inception
                        msgs.extend(self.makeOwnInception())

                msgs.extend(self.receipt(cuedSerder))
                yield msgs

            elif cueKin in ("replay",):
                msgs = cue["msgs"]
                yield msgs

            elif cueKin in ("reply", ):
                data = cue["data"]
                route = cue["route"]
                msg = self.reply(data=data, route=route)
                yield msg


class HabitatDoer(doing.Doer):
    """
    Basic Habitat Doer  to initialize habitat databases .ks and .db

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.

    Attributes:
        .habitat is Habitat subclass

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .exit is exit context method
        .close is close context method
        .abort is abort context method

    Hidden:
        ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
        ._tock is hidden attribute for .tock property
    """

    def __init__(self, habitat, **kwa):
        """
        Parameters:
           habitat (Habitat): instance
        """
        super(HabitatDoer, self).__init__(**kwa)
        self.habitat = habitat

    def enter(self):
        """"""
        if not self.habitat.inited:
            self.habitat.setup(**self.habitat._inits)

    def exit(self):
        """"""
        pass
