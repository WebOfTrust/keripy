# -*- encoding: utf-8 -*-
"""
keri.vc.proving module

"""

import json

import cbor2 as cbor
import msgpack

from .. import help
from ..core import coring
from ..core.coring import (Serials, sniff, Versify, Deversify, Rever, Counter,
                           CtrDex, Prefixer, Seqner, Diger, Siger, Saider, Ids)
from ..core.parsing import Parser, Colds
from ..core.scheming import JSONSchema
from ..kering import Version, VersionError, ShortageError, DeserializationError, ColdStartError, ExtractionError

KERI_REGISTRY_TYPE = "KERICredentialRegistry"

logger = help.ogler.getLogger()


def credential(schema,
               issuer,
               subject,
               source=None,
               status=None,
               typ=JSONSchema(),
               version=Version,
               kind=Serials.json):
    """
    Returns Credentialer of new credential
        schema is SAID of schema for this credential
        issuer is the identifier prefix of the issuer
        subject is dict of the values being assigned to the subject of this credential
        source is list of source credentials to which this credential is chained
        typ is schema type
        version is Version instance
        kind is serialization kind

    """
    vs = Versify(version=version, kind=kind, size=0)

    vc = dict(
        v=vs,
        i="",
        x=schema,
        ti=issuer,
        d=subject
    )

    if source is not None:
        vc["s"] = source

    if status is not None:
        vc["ri"] = status

    return Credentialer(crd=vc, typ=typ)


def parseCredential(ims=b'', wallet=None, typ=JSONSchema()):
    """
    Parse the ims bytearray as a CESR Proof Format verifiable credential

    Parameters:
        ims (bytearray) of serialized incoming verifiable credential in CESR Proof Format.
        wallet (Wallet) storage for the verified credential
        typ (JSONSchema) class for resolving schema references:

    """
    try:
        creder = Credentialer(raw=ims, typ=typ)
    except ShortageError as e:
        raise e
    else:
        del ims[:creder.size]
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

    if wallet is not None:
        wallet.processCredential(creder, prefixer, seqner, diger, isigers)

    return creder, prefixer, seqner, diger, isigers


def parseProof(ims=b''):
    cold = Parser.sniff(ims)
    if cold is Colds.msg:
        raise ColdStartError("unable to parse VC, attachments expected")

    ctr = Parser.extract(ims=ims, klas=Counter, cold=cold)
    if ctr.code != CtrDex.TransIndexedSigGroups or ctr.count != 1:
        raise ExtractionError("Invalid attachment to VC {}, expected one {}"
                              "".format(ctr.code, CtrDex.TransIndexedSigGroups))

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
    prf.extend(Counter(CtrDex.TransIndexedSigGroups, count=1).qb64b)
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

    def __init__(self, raw=b'', crd=None, kind=None, typ=JSONSchema(), code=coring.MtrDex.Blake3_256):
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
        self._typ = typ

        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
        elif crd:  # serialize ked using property setter
            self._kind = kind
            self.crd = crd  # ked property setter does the serialization
        else:
            raise ValueError("Improper initialization need raw or ked.")

        # try:
        #     scer = self._typ.resolve(self.crd["x"])
        #     schemer = Schemer(raw=scer, typ=self._typ)
        #
        #     if not schemer.verify(self.raw):
        #         raise ValidationError("subject is not valid against the schema")
        # except ValueError:
        #     logger.info("unable to load / validate schema")

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

        crd["i"] = Saider.Dummy * coring.Matter.Codes[coring.MtrDex.Blake3_256].fs

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

        saider = Saider(sad=crd, code=coring.MtrDex.Blake3_256, label=Ids.i)
        crd["i"] = saider.qb64

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
        self._saider = Saider(qb64=self._crd[Ids.i], code=coring.MtrDex.Blake3_256, label=Ids.i)

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
        return self.crd["ti"]

    @property
    def schema(self):
        """ schema property getter"""
        return self.crd["x"]

    @property
    def subject(self):
        """ subject property getter"""
        return self.crd["d"]

    @property
    def status(self):
        """ status property getter"""
        return self.crd["ri"]

    def pretty(self):
        """
        Returns str JSON of .ked with pretty formatting
        """
        return json.dumps(self.crd, indent=1)
