# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module

"""
from dataclasses import dataclass, field, asdict
from datetime import datetime

import json
import cbor2 as cbor
import msgpack

from keri.core import coring
from keri.core.coring import Serials, sniff, Versify, Deversify, Rever
from keri.core.scheming import Saider, Ids, Schemer
from keri.help import helping
from keri.kering import ValidationError, Version, VersionError, ShortageError, DeserializationError

KERI_REGISTRY_TYPE = "KERICredentialRegistry"


@dataclass
class Credential:

    vs: str = field(default=Versify(version=Version, kind=Serials.json, size=0))
    pre: str = field(default="")
    regk: str = field(default="")
    schemer: Schemer = field(default=None)
    subject: dict = field(default_factory=dict())
    issuance: datetime = field(default=helping.nowUTC())
    expiry: datetime = field(default=None)

    def asdict(self):
        d = dict(
            id="",
            type=[self.schemer.said],
            issuer=self.pre,
            issuanceDate=helping.toIso8601(self.issuance),
            credentialSubject=self.subject,
            credentialStatus=dict(
                id=self.regk,
                type=KERI_REGISTRY_TYPE
            )
        )

        if self.expiry is not None:
            d["expirationDate"] = helping.toIso8601(self.expiry)

        # TODO: stop being opinionated about the SAID hash algo
        saider = Saider(sed=d, code=coring.MtrDex.Blake3_256, kind=Ids.id)
        d["id"] = saider.qb64

        vc = dict(
            vs=self.vs,
            x=self.schemer.said,
            d=d
        )

        return vc


class Credentialer:
    """
    Credentialer is for creating a W3C Verifiable Credential embedded in a CESR Proof Format
    proof

    """
    def __init__(self, raw=b'', crd: Credential = None, kind=None, code=coring.MtrDex.Blake3_256):
        """

        """
        self._code = code  # need default code for .diger
        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
        elif crd:  # serialize ked using property setter
            self._kind = kind
            self.crd = crd  # ked property setter does the serialization
        else:
            raise ValueError("Improper initialization need raw or ked.")

        subr = json.dumps(self.crd.subject).encode("utf-8")
        if not self.crd.schemer.verify(subr):
            raise ValidationError("subject is not valid against the schema")



    @staticmethod
    def _inhale(raw):
        kind, version, size = sniff(raw)
        if version != Version:
            raise VersionError("Unsupported version = {}.{}, expected {}."
                               "".format(version.major, version.minor, Version))
        if len(raw) < size:
            raise ShortageError("Need more bytes.")

        if kind == Serials.json:
            try:
                vc = json.loads(raw[:size].decode("utf-8"))
            except Exception:
                raise DeserializationError("Error deserializing JSON: {}"
                                           "".format(raw[:size].decode("utf-8")))

        elif kind == Serials.mgpk:
            try:
                vc = msgpack.loads(raw[:size])
            except Exception:
                raise DeserializationError("Error deserializing MGPK: {}"
                                           "".format(raw[:size]))

        elif kind == Serials.cbor:
            try:
                vc = cbor.loads(raw[:size])
            except Exception:
                raise DeserializationError("Error deserializing CBOR: {}"
                                           "".format(raw[:size]))

        else:
            raise DeserializationError("Error deserializing unsupported kind: {}"
                                       "".format(raw[:size].decode("utf-8")))

        #  said = vc["x"]
        ced = vc["d"]

        # TODO: how to load schema to create Schemar
        pre = ced["pre"]
        subject = ced["credentialSubject"]

        if "issuanceDate" in ced:
            issuance = helping.fromIso8601(ced["issuanceDate"])
        else:
            issuance = None

        if "expirationDate" in ced:
            expiry = helping.fromIso8601(ced["expirationDate"])
        else:
            expiry = None


        regk = None
        if "credentialStatus" in ced:
            cs = ced["credentialStatus"]
            if cs["type"] == KERI_REGISTRY_TYPE:
                regk = cs["id"]

        crd = Credential(pre=pre,
                         regk=regk,
                         schemer=Schemer(),
                         subject=subject,
                         issuance=issuance,
                         expiry=expiry)

        return crd, kind, version, size



    @staticmethod
    def _exhale(crd, kind=None):

        knd, version, size = Deversify(crd.vs)  # extract kind and version
        if version != Version:
            raise ValueError("Unsupported version = {}.{}".format(version.major,
                                                                  version.minor))

        if not kind:
            kind = knd

        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        vc = crd.asdict()

        if kind == Serials.json:
            raw = json.dumps(vc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        elif kind == Serials.mgpk:
            raw = msgpack.dumps(vc)

        elif kind == Serials.cbor:
            raw = cbor.dumps(vc)

        else:
            raise ValueError("Invalid serialization kind = {}".format(kind))

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
        crd.vs = vs

        return raw, kind, crd, version



    @property
    def raw(self):
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        crd, kind, version, size = self._inhale(raw=raw)
        self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
        self._crd = crd
        self._kind = kind
        self._version = version
        self._saider = Saider(ser=self._raw, code=self._code)


    @property
    def crd(self):
        """ crd property getter"""
        return self._crd


    @crd.setter
    def crd(self, crd):
        """ ked property setter  assumes ._kind """
        raw, kind, crd, version = self._exhale(crd=crd, kind=self._kind)
        size = len(raw)
        self._raw = raw[:size]
        self._crd = crd
        self._kind = kind
        self._size = size
        self._version = version
        self._saider = Saider(sed=crd.asdict(), code=self._code)
