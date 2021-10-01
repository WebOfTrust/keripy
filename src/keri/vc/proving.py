# -*- encoding: utf-8 -*-
"""
keri.vc.proving module

"""

import json
import logging
from collections.abc import Iterable
from typing import Union

import cbor2 as cbor
import msgpack

from .. import help, kering
from ..core import coring
from ..core.coring import (Serials, sniff, Versify, Deversify, Rever, Counter,
                           CtrDex, Prefixer, Seqner, Diger, Siger, Saider, Ids)
from ..core.parsing import Parser, Colds
from ..db import subing
from ..kering import Version, VersionError, ShortageError, DeserializationError, ColdStartError, ExtractionError

KERI_REGISTRY_TYPE = "KERICredentialRegistry"

logger = help.ogler.getLogger()


def credential(schema,
               issuer,
               subject,
               status=None,
               source=None,
               version=Version,
               kind=Serials.json):
    """
    Returns Credentialer of new credential
        schema is SAID of schema for this credential
        issuer is the identifier prefix of the issuer
        subject is dict of the values being assigned to the subject of this credential
        source is list of source credentials to which this credential is chained
        version is Version instance
        kind is serialization kind

    """
    vs = Versify(version=version, kind=kind, size=0)

    source = source if source is not None else []

    vc = dict(
        v=vs,
        d="",
        s=schema,
        i=issuer,
        a={},
        p=source
    )

    if status is not None:
        subject["ri"] = status

    _, sad = coring.Saider.saidify(sad=subject, kind=kind, label=coring.Ids.d)
    vc["a"] = sad

    return Credentialer(crd=vc)


def parseCredential(ims, verifier):
    parsator = allParsator(ims=ims, verifier=verifier)

    while True:
        try:
            next(parsator)
        except StopIteration:
            break


def allParsator(ims, verifier):
    if not isinstance(ims, bytearray):
        ims = bytearray(ims)  # so make bytearray copy

    while ims:  # only process until ims empty
        try:
            done = yield from credParsator(ims=ims,
                                           verifier=verifier,
                                           )

        except kering.SizedGroupError as ex:  # error inside sized group
            # processOneIter already flushed group so do not flush stream
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Parser msg extraction error: %s\n", ex.args[0])
            else:
                logger.error("Parser msg extraction error: %s\n", ex.args[0])

        except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Parser msg extraction error: %s\n", ex.args[0])
            else:
                logger.error("Parser msg extraction error: %s\n", ex.args[0])
            del ims[:]  # delete rest of stream to force cold restart

        except (kering.ValidationError, Exception) as ex:  # non Extraction Error
            # Non extraction errors happen after successfully extracted from stream
            # so we don't flush rest of stream just resume
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Parser msg non-extraction error: %s\n", ex)
            else:
                logger.error("Parser msg non-extraction error: %s\n", ex)
        yield

    return True



def credentialParsator(ims, verifier):
    if not isinstance(ims, bytearray):
        ims = bytearray(ims)  # so make bytearray copy

        while True:  # continuous stream processing never stop
            try:
                done = yield from credParsator(ims=ims,
                                               verifier=verifier)

            except kering.SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s\n", ex.args[0])

            except (kering.ColdStartError, kering.ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Parser msg extraction error: %s\n", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (kering.ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Parser msg non-extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Parser msg non-extraction error: %s\n", ex.args[0])
            yield



def credParsator(ims=b'', verifier=None):
    """
    Parse the ims bytearray as a CESR Proof Format verifiable credential

    Parameters:
        ims (bytearray) of serialized incoming verifiable credential in CESR Proof Format.
        verifier (verifying.Verifier) verifier and storage for the verified credential
        typ (JSONSchema) class for resolving schema references:

    """

    while not ims:
        yield

    cold = Parser.sniff(ims)  # check for spurious counters at front of stream
    if cold in (Colds.txt, Colds.bny):  # not message error out to flush stream
        # replace with pipelining here once CESR message format supported.
        raise kering.ColdStartError("Expecting message counter tritet={}"
                                    "".format(cold))

    while True:  # extract and deserialize message from ims
        try:
            creder = Credentialer(raw=ims)
        except ShortageError as e:
            raise e
        else:
            del ims[:creder.size]
            break


    # extract attachments must start with counter so know if txt or bny.
    while not ims:
        yield
    cold = Parser.sniff(ims)
    if cold is Colds.msg:
        raise ColdStartError("unable to parse VC, attachments expected")

    ctr = Parser.extract(ims=ims, klas=Counter, cold=cold)
    if ctr.code != CtrDex.AttachedMaterialQuadlets:
        raise ExtractionError("Invalid attachment to VC {}, expected {}"
                              "".format(ctr.code, CtrDex.AttachedMaterialQuadlets))

    pags = ctr.count * 4
    if len(ims) != pags:
        raise ShortageError("VC proof attachment invalid length {}, expected {}"
                            "".format(len(ims), pags))

    prefixer, seqner, diger, isigers = parseProof(ims=ims)

    try:
        verifier.processCredential(creder, prefixer, seqner, diger, isigers)
    except AttributeError as ex:
        raise kering.ValidationError("No verifier to process so dropped credential"
                                     "= {}.".format(creder.pretty()))

    return True  # done state


def parseProof(ims=b''):
    cold = Parser.sniff(ims)
    if cold is Colds.msg:
        raise ColdStartError("unable to parse VC, attachments expected")

    ctr = Parser.extract(ims=ims, klas=Counter, cold=cold)
    if ctr.code != CtrDex.TransIdxSigGroups or ctr.count != 1:
        raise ExtractionError("Invalid attachment to VC {}, expected one {}"
                              "".format(ctr.code, CtrDex.TransIdxSigGroups))

    prefixer = Parser.extract(ims=ims, klas=Prefixer)
    seqner = Parser.extract(ims=ims, klas=Seqner)
    diger = Parser.extract(ims=ims, klas=Diger)

    ictr = Parser.extract(ims=ims, klas=Counter)
    if ictr.code != CtrDex.ControllerIdxSigs:
        raise ExtractionError("Invalid attachment to VC {}, expected {}"
                              "".format(ctr.code, CtrDex.ControllerIdxSigs))

    isigers = []
    for i in range(ictr.count):
        isiger = Parser.extract(ims=ims, klas=Siger)
        isigers.append(isiger)

    return prefixer, seqner, diger, isigers


def buildProof(prefixer, seqner, diger, sigers):
    """

    Parameters:
        prefixer (Prefixer) Identifier of the issuer of the credential
        seqner (Seqner) is the sequence number of the event used to sign the credential
        diger (Diger) is the digest of the event used to sign the credential
        sigers (list) are the cryptographic signatures on the credential

    """

    prf = bytearray()
    prf.extend(Counter(CtrDex.TransIdxSigGroups, count=1).qb64b)
    prf.extend(prefixer.qb64b)
    prf.extend(seqner.qb64b)
    prf.extend(diger.qb64b)

    prf.extend(Counter(code=CtrDex.ControllerIdxSigs, count=len(sigers)).qb64b)
    for siger in sigers:
        prf.extend(siger.qb64b)

    return prf


class Credentialer:
    """
    Credentialer is for creating a W3C Verifiable Credential embedded in a CESR Proof Format
    proof

    """

    def __init__(self, raw=b'', crd=None, kind=None, code=coring.MtrDex.Blake3_256):
        """
        Creates a serializer/deserializer for a Verifiable Credential in CESR Proof Format

        requires either raw or (crd and kind) to load credential from serialized form or in memory

        Parameters:
            raw (bytes) is raw credential
            crd (dict) is populated credential
            typ is schema type
            version is Version instance
            kind is serialization kind

        """
        self._code = code  # need default code for .diger

        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
        elif crd:  # serialize ked using property setter
            self._kind = kind
            self.crd = crd  # ked property setter does the serialization
        else:
            raise ValueError("Improper initialization need raw or ked.")


    @staticmethod
    def _inhale(raw):
        """
        Parse raw according to serialization type and return dict of values, kind, version and size

        """
        kind, version, size = sniff(raw)
        if version != Version:
            raise VersionError("Unsupported version = {}.{}, expected {}."
                               "".format(version.major, version.minor, Version))
        if len(raw) < size:
            raise ShortageError("Need more bytes.")

        if kind == Serials.json:
            try:
                crd = json.loads(raw[:size].decode("utf-8"))
            except Exception:
                raise DeserializationError("Error deserializing JSON: {}"
                                           "".format(raw[:size].decode("utf-8")))

        elif kind == Serials.mgpk:
            try:
                crd = msgpack.loads(raw[:size])
            except Exception:
                raise DeserializationError("Error deserializing MGPK: {}"
                                           "".format(raw[:size]))

        elif kind == Serials.cbor:
            try:
                crd = cbor.loads(raw[:size])
            except Exception:
                raise DeserializationError("Error deserializing CBOR: {}"
                                           "".format(raw[:size]))

        else:
            raise DeserializationError("Error deserializing unsupported kind: {}"
                                       "".format(raw[:size].decode("utf-8")))

        return crd, kind, version, size

    @staticmethod
    def _exhale(crd, kind=None):
        """
        Create serialized format from dict of VC values.  Returns raw, kind, dict of values and version

        """

        knd, version, size = Deversify(crd["v"])  # extract kind and version
        if version != Version:
            raise ValueError("Unsupported version = {}.{}".format(version.major,
                                                                  version.minor))

        crd["d"] = Saider.Dummy * coring.Matter.Codes[coring.MtrDex.Blake3_256].fs

        if not kind:
            kind = knd

        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        raw = coring.dumps(crd, kind)
        size = len(raw)

        match = Rever.search(raw)
        if not match or match.start() > 12:
            raise ValueError("Invalid version string in raw = {}".format(raw))

        fore, back = match.span()

        # update vs with latest kind version size
        vs = Versify(version=version, kind=kind, size=size)
        # replace old version string in raw with new one
        raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
        if size != len(raw):  # substitution messed up
            raise ValueError("Malformed version string size = {}".format(vs))
        crd["v"] = vs

        saider = Saider(sad=crd, code=coring.MtrDex.Blake3_256, label=Ids.d)
        crd["d"] = saider.qb64

        raw = coring.dumps(crd, kind)

        return raw, kind, crd, version, saider

    @property
    def kind(self):
        """ kind property getter"""
        return self._kind

    @property
    def raw(self):
        """ raw gettter bytes of serialized type """
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        crd, kind, version, size = self._inhale(raw=raw)
        self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
        self._crd = crd
        self._kind = kind
        self._version = version
        self._size = size
        self._saider = Saider(qb64=self._crd[Ids.d], code=coring.MtrDex.Blake3_256, label=Ids.d)

    @property
    def crd(self):
        """ crd dict property getter"""
        return self._crd

    @crd.setter
    def crd(self, crd):
        """ ked property setter  assumes ._kind """
        raw, kind, crd, version, saider = self._exhale(crd=crd, kind=self._kind)
        size = len(raw)
        self._raw = raw[:size]
        self._crd = crd
        self._kind = kind
        self._size = size
        self._version = version
        self._saider = saider

    @property
    def size(self):
        """ size property getter"""
        return self._size

    @property
    def saider(self):
        """ saider property getter"""
        return self._saider

    @property
    def said(self):
        """ said property getter, relies on saider """
        return self.saider.qb64

    @property
    def issuer(self):
        """ issuer property getter"""
        return self.crd["i"]

    @property
    def schema(self):
        """ schema property getter"""
        return self.crd["s"]

    @property
    def subject(self):
        """ subject property getter"""
        return self.crd["a"]

    @property
    def status(self):
        """ status property getter"""
        return self.crd["a"]["ri"]

    def pretty(self):
        """
        Returns str JSON of .ked with pretty formatting
        """
        return json.dumps(self.crd, indent=1)


class CrederSuber(subing.Suber):
    """
    Sub class of Suber where data is serialized Credentialer instance
    Automatically serializes and deserializes using Credentialer methods

    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(CrederSuber, self).__init__(*pa, **kwa)


    def put(self, keys: Union[str, Iterable], val: Credentialer):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Credentialer): instance

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))


    def pin(self, keys: Union[str, Iterable], val: Credentialer):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Credentialer): instance

        Returns:
            result (bool): True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets Serder at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            Credentialer:
            None: if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (creder := mydb.get(keys)) is None:
                raise ExceptionHere
            use creder here

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return Credentialer(raw=bytes(val)) if val is not None else None


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return self.db.delVal(db=self.sdb, key=self._tokey(keys))


    def getItemIter(self, keys: Union[str, Iterable]=b""):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val coring.Serder for
            each entry in db

        """
        for key, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield self._tokeys(key), Credentialer(raw=bytes(val))
