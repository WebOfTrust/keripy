# -*- encoding: utf-8 -*-
"""
keri.core.scheming module

self-addressing and schema support
"""

import blake3
import hashlib
import jsonschema

from collections import namedtuple

import json
import cbor2 as cbor
import msgpack

from .coring import Matter, MtrDex, Serials
from ..kering import ValidationError, DeserializationError, EmptyMaterialError

Idage = namedtuple("Idage", "dollar at id")

Ids = Idage(dollar="$id", at="@id", id="id")


class JSONSchema:

    id = Ids.dollar

    def __init__(self, resolver=None):
        self.resolver = resolver

    def load(self, raw=b'', kind=Serials.json):
        if kind == Serials.json:
            try:
                sed = json.loads(raw.decode("utf-8"))
            except Exception as ex:
                raise DeserializationError("Error deserializing JSON: {}"
                      "".format(raw.decode("utf-8")))

        elif kind == Serials.mgpk:
            try:
                sed = msgpack.loads(raw)
            except Exception as ex:
                raise DeserializationError("Error deserializing MGPK: {}"
                      "".format(raw))

        elif kind == Serials.cbor:
            try:
                sed = cbor.loads(raw)
            except Exception as ex:
                raise DeserializationError("Error deserializing CBOR: {}"
                      "".format(raw))
        else:
            raise ValueError("Invalid serialization kind = {}".format(kind))


        if self.id in sed:
            saider = Saider(qb64=sed[self.id])
            said = sed[self.id]
            if not saider.verify(sed, prefixed=True):
                raise ValidationError("invalid self-addressing identifier {} in schema = {}"
                                      "".format(said, sed))
        else:
            raise ValidationError("missing ID field {} in schema = {}"
                                  "".format(self.id, sed))

        return sed, kind, saider

    @staticmethod
    def dump(sed, kind=Serials.json):

        if kind == Serials.json:
            raw = json.dumps(sed, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        elif kind == Serials.mgpk:
            raw = msgpack.dumps(sed)

        elif kind == Serials.cbor:
            raw = cbor.dumps(sed)
        else:
            raise ValueError("Invalid serialization kind = {}".format(kind))


        return raw


    @staticmethod
    def detect(raw=b''):
        """
        Returns True if content represents JSON Schema by checking
            for $schema;  False otherwise
        """

        try:
            raw.index(b'"$schema"')
        except ValueError:
            return False

        return True


    @staticmethod
    def verify_schema(schema):
        """
        Returns True if the provided schema validates successfully
          as complaint Draft 7 JSON Schema False otherwise

        Parameters:
            schema (dict): is the JSON schema to verify
        """
        try:
            jsonschema.Draft7Validator.check_schema(schema=schema)
        except jsonschema.exceptions.SchemaError:
            return False

        return True


    def verify_json(self, schema=b'', raw=b''):
        """
        Returns True if the JSON passes validation against the
           provided complaint Draft 7 JSON Schema.  Returns False
           if raw is not valid JSON, schema is not valid JSON Schema or
           the validation fails

        Parameters:
              schema (bytes): is the schema use for validation
              raw (bytes): is JSON to validate against the Schema
        """
        try:
            d = json.loads(raw)
            jsonschema.validate(instance=d, schema=schema, resolver=self.resolver)
        except jsonschema.exceptions.ValidationError:
            return False
        except jsonschema.exceptions.SchemaError:
            return False
        except json.decoder.JSONDecodeError:
            return False

        return True




class Schemer:
    """
    Schemer is KERI schema serializer-deserializer class
    Verifies self-addressing identifier base on schema type
    Only supports current version VERSION

    Has the following public properties:

    Properties:
        .raw is bytes of serialized event only
        .sed is JSON schema dict
        .kind is Schema kind string value (see namedtuple coring.Serials)
        .saider is Saider instance of self-addressing identifier
        .said  is qb64 digest from .saider

    Hidden Attributes:
          ._raw is bytes of serialized schema only
          ._sed is JSON schema dict
          ._kind is schema kind string value (see namedtuple coring.Serials)
            supported kinds are 'JSONSchema'
          ._code is default code for .saider
          ._saider is Saider instance of digest of .raw


    """

    def __init__(self, raw=b'', sed=None, kind=None, typ=JSONSchema(), code=MtrDex.Blake3_256):
        """
        Deserialize if raw provided
        Serialize if sed provided but not raw
        When serilaizing if kind provided then use kind instead of field in sed

        Parameters:
          raw is bytes of serialized schema
          sed is JSON dict or None
            if None its deserialized from raw
          schemaType is the type of schema
          kind is serialization kind string value or None (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
            if kind is None then its extracted from ked or raw
          code is .saider default digest code

        """

        self._code = code
        self.typ = typ
        if raw:
            self.raw = raw
        elif sed:
            self._kind = kind
            self.sed = sed
        else:
            raise ValueError("Improper initialization need raw or sed.")

        if not self._verify_schema():
            raise ValidationError("invalid kind {} for schema {}"
                                  "".format(self.kind, self.sed))


    def _inhale(self, raw):
        """
        Loads type specific Schema ked and verifies the self-addressing identifier
            of the raw content

        Parameters:
            raw: JSON to load

        """

        sed, kind, saider = self.typ.load(raw=raw)

        return sed, kind, saider


    def _exhale(self, sed, kind=None):
        """
        Dumps type specific Schema JSON and returns the raw bytes, sed
           and schema kind

        Parameters:
            sed: JSON to load
            kind (Schema) tuple of schema type

        """

        raw = self.typ.dump(sed)

        return raw, sed, kind


    @property
    def raw(self):
        """ raw property getter """
        return self._raw


    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        sed, kind, saider = self._inhale(raw=raw)
        self._raw = bytes(raw)  # crypto ops require bytes not bytearray
        self._sed = sed
        self._kind = kind
        self._saider = saider


    @property
    def sed(self):
        """ ked property getter"""
        return self._sed


    @sed.setter
    def sed(self, sed):
        """ ked property setter  assumes ._kind """
        raw, sed, kind = self._exhale(sed=sed, kind=self._kind)
        self._raw = raw
        self._kind = kind
        self._sed = sed
        self._saider = Saider(sed=self._sed, code=self._code)


    @property
    def kind(self):
        """ kind property getter """
        return self._kind


    @kind.setter
    def kind(self, kind):
        """ kind property setter Assumes ._ked """
        raw, kind, sed = self._exhale(sed=self._sed, kind=kind)
        self._raw = raw
        self._sed = sed
        self._kind = kind
        self._saider = Saider(raw=self._raw, code=self._code)


    @property
    def saider(self):
        """ saider property getter """
        return self._saider


    @property
    def said(self):
        """ said property getter, relies on saider """
        return self.saider.qb64


    def verify(self, raw=b''):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        Parameters:
            raw (bytes): is serialised JSON content to verify against schema
        """

        return self.typ.verify_json(schema=self.sed, raw=raw)

    def _verify_schema(self):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        """

        return self.typ.verify_schema(schema=self.sed)


class Saider(Matter):
    """
    Saider is Matter subclass for self-addressing identifier prefix using
    derivation as determined by code from ked
    """

    Dummy = "#"  # dummy spaceholder char for pre. Must not be a valid Base64 char

    def __init__(self, raw=None, code=None, sed=None, kind=Ids.dollar, **kwa):
        """

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code

        Parameters:
            sed (dict): optional deserialized JSON for which to create the self addressing
        """


        self.kind = kind
        try:
            # raw is populated
            super(Saider, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            # No raw, try and calculate code and said

            if not sed or (not code and self.kind not in sed):  # No sed or no code and no id in sed, no luck
                raise ex

            if not code:
                super(Saider, self).__init__(qb64=sed[kind], code=code, **kwa)
                code = self.code

            if code == MtrDex.Blake3_256:
                self._derive = self._derive_blake3_256
            elif code == MtrDex.Blake2b_256:
                self._derive = self._derive_blake2b_256
            elif code == MtrDex.Blake2s_256:
                self._derive = self._derive_blake2s_256
            elif code == MtrDex.SHA2_256:
                self._derive = self._derive_sha2_256
            elif code == MtrDex.SHA2_512:
                self._derive = self._derive_sha2_512
            elif code == MtrDex.SHA3_256:
                self._derive = self._derive_sha3_256
            elif code == MtrDex.SHA3_512:
                self._derive = self._derive_sha3_512
            else:
                raise ValueError("Unsupported code = {} for saider.".format(code))

            # use ked and ._derive from code to derive aid prefix and code
            raw, code = self._derive(sed=sed)
            super(Saider, self).__init__(raw=raw, code=code, **kwa)


        if self.code == MtrDex.Blake3_256:
            self._verify = self._verify_blake3_256
        elif self.code == MtrDex.Blake2b_256:
            self._verify = self._verify_blake2b_256
        elif self.code == MtrDex.Blake2s_256:
            self._verify = self._verify_blake2s_256
        elif self.code == MtrDex.SHA3_256:
            self._verify = self._verify_sha3_256
        elif self.code == MtrDex.SHA3_512:
            self._verify = self._verify_sha3_512
        elif self.code == MtrDex.SHA2_256:
            self._verify = self._verify_sha2_256
        elif self.code == MtrDex.SHA2_512:
            self._verify = self._verify_sha2_512
        else:
            raise ValueError("Unsupported code = {} for saider.".format(self.code))

    def derive(self, sed):
        """
        Returns tuple (raw, code) of said as derived from serialized dict sed.
                uses a derivation code specific _derive method

        Parameters:
            sed is json dict

        """

        return self._derive(sed=sed)


    def verify(self, sed, prefixed=False):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ID value matches .qb64
                False otherwise

        Parameters:
            sed (dict) is json dict
            prefixed (boolean) indicates whether to verify ID value matched .qb64
        """
        try:
            said = self.qb64
            crymat = self._verify(sed=sed)
            if crymat.qb64 != said:
                return False

            idf = self.kind
            if prefixed and sed[idf] != said:
                return False

        except Exception as ex:
            return False

        return True


    def _derive_blake3_256(self, sed):
        """
        Returns tuple (raw, code) of basic Blake3 digest (qb64)
            as derived from json dict sed
        """
        sed = dict(sed)  # make copy so don't clobber original sed

        idf = self.kind
        # put in dummy pre to get size correct
        sed[idf] = "{}".format(self.Dummy*Matter.Codes[MtrDex.Blake3_256].fs)
        raw = json.dumps(sed).encode("utf-8")

        dig = blake3.blake3(raw).digest()
        return dig, MtrDex.Blake3_256


    def _verify_blake3_256(self, sed):
        """
        Returns Matter of typed cryptographic material

        Parameters:
            sed is inception key event dict
        """
        raw, code = self._derive_blake3_256(sed=sed)
        return Matter(raw=raw, code=MtrDex.Blake3_256)


    def _derive_sha3_256(self, sed):
        """
        Returns tuple (raw, code) of basic SHA3 digest (qb64)
            as derived from json dict sed
        """
        sed = dict(sed)  # make copy so don't clobber original sed

        idf = self.kind
        # put in dummy pre to get size correct
        sed[idf] = "{}".format(self.Dummy*Matter.Codes[MtrDex.SHA3_256].fs)
        raw = json.dumps(sed).encode("utf-8")

        dig = hashlib.sha3_256(raw).digest()
        return dig, MtrDex.SHA3_256


    def _verify_sha3_256(self, sed):
        """
        Returns Matter of typed cryptographic material

        Parameters:
            sed is inception key event dict
        """
        raw, code = self._derive_sha3_256(sed=sed)
        return Matter(raw=raw, code=MtrDex.SHA3_256)


    def _derive_sha3_512(self, sed):
        """
        Returns tuple (raw, code) of basic SHA3 digest (qb64)
            as derived from json dict sed
        """
        sed = dict(sed)  # make copy so don't clobber original sed

        idf = self.kind
        # put in dummy pre to get size correct
        sed[idf] = "{}".format(self.Dummy*Matter.Codes[MtrDex.SHA3_512].fs)
        raw = json.dumps(sed).encode("utf-8")

        dig = hashlib.sha3_512(raw).digest()
        return dig, MtrDex.SHA3_512


    def _verify_sha3_512(self, sed):
        """
        Returns Matter of typed cryptographic material

        Parameters:
            sed is inception key event dict
        """
        raw, code = self._derive_sha3_512(sed=sed)
        return Matter(raw=raw, code=MtrDex.SHA3_512)


    def _derive_sha2_256(self, sed):
        """
        Returns tuple (raw, code) of basic SHA2 digest (qb64)
            as derived from json dict sed
        """
        sed = dict(sed)  # make copy so don't clobber original sed

        idf = self.kind
        # put in dummy pre to get size correct
        sed[idf] = "{}".format(self.Dummy*Matter.Codes[MtrDex.SHA2_256].fs)
        raw = json.dumps(sed).encode("utf-8")

        dig = hashlib.sha256(raw).digest()
        return dig, MtrDex.SHA2_256


    def _verify_sha2_256(self, sed):
        """
        Returns Matter of typed cryptographic material

        Parameters:
            sed is schema JSON dict
        """
        raw, code = self._derive_sha2_256(sed=sed)
        return Matter(raw=raw, code=MtrDex.SHA2_256)


    def _derive_sha2_512(self, sed):
        """
        Returns tuple (raw, code) of basic SHA2 digest (qb64)
            as derived from json dict sed
        """
        sed = dict(sed)  # make copy so don't clobber original sed

        idf = self.kind
        # put in dummy pre to get size correct
        sed[idf] = "{}".format(self.Dummy*Matter.Codes[MtrDex.SHA2_512].fs)
        raw = json.dumps(sed).encode("utf-8")

        dig = hashlib.sha512(raw).digest()
        return dig, MtrDex.SHA2_512


    def _verify_sha2_512(self, sed):
        """
        Returns Matter of typed cryptographic material

        Parameters:
            sed is inception key event dict
            said is Base64 fully qualified default to .qb64
        """
        raw, code = self._derive_sha2_512(sed=sed)
        return Matter(raw=raw, code=MtrDex.SHA2_512)


    def _derive_blake2b_256(self, sed):
        """
        Returns tuple (raw, code) of basic BLAKE2B digest (qb64)
            as derived from json dict sed
        """
        sed = dict(sed)  # make copy so don't clobber original sed

        idf = self.kind
        # put in dummy pre to get size correct
        sed[idf] = "{}".format(self.Dummy*Matter.Codes[MtrDex.Blake2b_256].fs)
        raw = json.dumps(sed).encode("utf-8")

        dig = hashlib.blake2b(raw).digest()
        return dig, MtrDex.Blake2b_256


    def _verify_blake2b_256(self, sed):
        """
        Returns Matter of typed cryptographic material

        Parameters:
            sed is inception key event dict
        """
        raw, code = self._derive_blake2b_256(sed=sed)
        return Matter(raw=raw, code=MtrDex.Blake2b_256)


    def _derive_blake2s_256(self, sed):
        """
        Returns tuple (raw, code) of basic BLAKE2S digest (qb64)
            as derived from json dict sed
        """
        sed = dict(sed)  # make copy so don't clobber original sed

        idf = self.kind
        # put in dummy pre to get size correct
        sed[idf] = "{}".format(self.Dummy*Matter.Codes[MtrDex.Blake2s_256].fs)
        raw = json.dumps(sed).encode("utf-8")

        dig = hashlib.blake2s(raw).digest()
        return dig, MtrDex.Blake2s_256


    def _verify_blake2s_256(self, sed):
        """
        Returns Matter of typed cryptographic material

        Parameters:
            sed is inception key event dict
        """
        raw, code = self._derive_blake2s_256(sed=sed)
        return Matter(raw=raw, code=MtrDex.Blake2s_256)


class CacheResolver:
    """
    Sample jsonschema resolver for loading schema $ref references from a local hash.

    """

    def __init__(self, cache=None):
        """
        Create a jsonschema resolver that can be used for loading references to schema remotely.

        Parameters:
            cache (dict) is an optional pre-loaded cache of schema
        """
        self.cache = cache if cache is not None else dict()

    def add(self, key, schema):
        """
        Add schema to cache for resolution

        Parameters:
            key (str) URI to resolve to the schema
            schema (bytes) is bytes of the schema for the URI
        """
        self.cache[key] = schema

    def handler(self, uri):
        """
        Handler provided to jsonschema for cache resolution

        Parameters:
            uri (str) the URI to resolve
        """
        if uri not in self.cache:
            raise ValueError("{} ref not found".format(uri))

        ref = self.cache[uri]
        schemr = Schemer(raw=ref)
        return schemr.sed

    def resolver(self, scer=b''):
        """
        Returns a jsonschema resolver for returning locally cached schema based on self-addressing
        identifier URIs.

        Parameters:
            scer (bytes) is the source document that is being processed for reference resolution

        """
        return jsonschema.RefResolver("", scer, handlers={"did": self.handler})